# Copyright 2022 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Optional

from autobahn.exception import Disconnected
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.websocket import ConnectionRequest
from pydantic import ValidationError
from structlog import get_logger
from typing_extensions import assert_never

from hathor.event.websocket.request import AckRequest, Request, RequestWrapper, StartStreamRequest, StopStreamRequest
from hathor.event.websocket.response import EventResponse, InvalidRequestResponse, InvalidRequestType, Response
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.event.websocket import EventWebsocketFactory

logger = get_logger()


class EventWebsocketProtocol(WebSocketServerProtocol):
    """WebSocket protocol that handles Event Queue feature commands."""

    factory: 'EventWebsocketFactory'

    # The peer connected to this connection.
    client_peer: Optional[str] = None

    # The last event id that was sent to this connection.
    _last_sent_event_id: Optional[int] = None

    # The last event id that was acknowledged by this connection.
    _ack_event_id: Optional[int] = None

    # The amount of events this connection can process. Essentially, its flux control.
    _window_size: int = 0

    # Whether the stream is enabled or not.
    _stream_is_active: bool = False

    def __init__(self) -> None:
        super().__init__()
        self.log = logger.new()

    def can_receive_event(self, event_id: int) -> bool:
        """
        Returns whether this client is available to receive an event.
        Only the next expected event can be sent, if the stream is active. Also, there needs to be more slots in the
        configured window than events that were sent but not acknowledged yet.
        """
        number_of_pending_events = 0

        if self._last_sent_event_id is not None:
            ack_offset = -1 if self._ack_event_id is None else self._ack_event_id
            number_of_pending_events = self._last_sent_event_id - ack_offset

        return (
            self._stream_is_active
            and event_id == self.next_expected_event_id()
            and number_of_pending_events < self._window_size
        )

    def next_expected_event_id(self) -> int:
        """Returns the ID of the next event the client expects."""
        return 0 if self._last_sent_event_id is None else self._last_sent_event_id + 1

    def onConnect(self, request: ConnectionRequest) -> None:
        self.client_peer = request.peer
        self.log = self.log.new(client_peer=self.client_peer)
        self.log.info('connection opened to the event websocket, starting handshake...')

    def onOpen(self) -> None:
        self.log.info('connection established to the event websocket')
        self.factory.register(self)

    def onClose(self, wasClean: bool, code: int, reason: str) -> None:
        self.log.info('connection closed to the event websocket', reason=reason)
        self.factory.unregister(self)

    def onMessage(self, payload: bytes, isBinary: bool) -> None:
        self.log.debug('message', payload=payload.hex() if isBinary else payload.decode('utf8'))

        try:
            request = RequestWrapper.parse_raw_request(payload)
            self._handle_request(request)
        except ValidationError as error:
            self.send_invalid_request_response(InvalidRequestType.VALIDATION_ERROR, payload, str(error))
        except InvalidRequestError as error:
            self.send_invalid_request_response(error.type, payload)

    def _handle_request(self, request: Request) -> None:
        """Handles a request message according to its type."""
        match request:
            case StartStreamRequest(): self._handle_start_stream_request(request)
            case AckRequest(): self._handle_ack_request(request)
            case StopStreamRequest(): self._handle_stop_stream_request()
            case _: assert_never(request)

    def _handle_start_stream_request(self, request: StartStreamRequest) -> None:
        """
        Handles a StartStreamRequest message.
        Sets all required state attributes and triggers the factory's recursion to send events while it's possible.
        """
        if self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_ACTIVE)

        self._last_sent_event_id = request.last_ack_event_id
        self._update_ack(request.last_ack_event_id)
        self._window_size = request.window_size
        self._stream_is_active = True

        self.factory.send_next_event_to_connection(self)

    def _handle_ack_request(self, request: AckRequest) -> None:
        """
        Handles an AckRequest message.
        Updates state attributes and triggers the factory's recursion to send events while it's possible
        """
        if not self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_INACTIVE)

        self._update_ack(request.ack_event_id)
        self._last_sent_event_id = request.ack_event_id
        self._window_size = request.window_size

        self.factory.send_next_event_to_connection(self)

    def _handle_stop_stream_request(self) -> None:
        """Handles a StopStreamRequest message."""
        if not self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_INACTIVE)

        self._stream_is_active = False

    def _update_ack(self, ack_event_id: Optional[int]) -> None:
        """Update the _ack_event_id if the new one is valid.

        The ack_event_id must be greater than the last ack we've received,
        and can't be greater than the last event we've sent.
        """
        if self._ack_event_id is not None and (
            ack_event_id is None or ack_event_id <= self._ack_event_id
        ):
            raise InvalidRequestError(InvalidRequestType.ACK_TOO_SMALL)

        if ack_event_id is not None and (
            self._last_sent_event_id is None or self._last_sent_event_id < ack_event_id
        ):
            raise InvalidRequestError(InvalidRequestType.ACK_TOO_LARGE)

        self._ack_event_id = ack_event_id

    def send_event_response(self, event_response: EventResponse) -> None:
        """Send an EventResponse to this connection."""
        self._send_response(event_response)
        self._last_sent_event_id = event_response.event.id

    def send_invalid_request_response(
        self,
        _type: InvalidRequestType,
        invalid_payload: Optional[bytes] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Send an InvalidRequestResponse to this connection."""
        invalid_request = None if invalid_payload is None else invalid_payload.decode('utf8')
        response = InvalidRequestResponse(
            type=_type,
            invalid_request=invalid_request,
            error_message=error_message
        )

        self._send_response(response)

    def _send_response(self, response: Response) -> None:
        """Actually sends a response to this connection."""
        payload = json_dumpb(response.model_dump())

        try:
            self.sendMessage(payload)
        except Disconnected:
            # Connection is closed. Nothing to do.
            pass
        # XXX: unfortunately autobahn can raise 3 different exceptions and one of them is a bare Exception
        # https://github.com/crossbario/autobahn-python/blob/v20.12.3/autobahn/websocket/protocol.py#L2201-L2294
        except Exception:
            self.log.error('send failed, moving on', exc_info=True)


class InvalidRequestError(Exception):
    def __init__(self, _type: InvalidRequestType):
        self.type = _type
