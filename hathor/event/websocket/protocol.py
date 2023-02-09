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

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.websocket import ConnectionRequest
from pydantic import ValidationError
from structlog import get_logger

from hathor.event.websocket.request import AckRequest, Request, RequestWrapper, StartStreamRequest, StopStreamRequest
from hathor.event.websocket.response import EventResponse, InvalidRequestResponse, InvalidRequestType, Response
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.event.websocket import EventWebsocketFactory

logger = get_logger()


class EventWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol, basically forwards some events to the Websocket factory.
    """

    factory: EventWebsocketFactory
    client_peer: Optional[str] = None

    _last_sent_event_id: Optional[int] = None
    _ack_event_id: Optional[int] = None
    _window_size: int = 0
    _stream_is_active: bool = False

    def __init__(self):
        super().__init__()
        self.log = logger.new()

    def can_receive_event(self, event_id: int) -> bool:
        """Returns whether this client is available to receive an event."""
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
        match request:
            case StartStreamRequest():
                self._handle_start_stream_request(request)
            case AckRequest():
                self._handle_ack_request(request)
            case StopStreamRequest():
                self._handle_stop_stream_request()

    def _handle_start_stream_request(self, request: StartStreamRequest) -> None:
        if self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_ACTIVE)

        self._validate_ack(request.last_ack_event_id)

        self._last_sent_event_id = request.last_ack_event_id
        self._ack_event_id = request.last_ack_event_id
        self._window_size = request.window_size
        self._stream_is_active = True

        self.factory.send_next_event_to_connection(self)

    def _handle_ack_request(self, request: AckRequest) -> None:
        if not self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_INACTIVE)

        self._validate_ack(request.ack_event_id)

        self._ack_event_id = request.ack_event_id
        self._window_size = request.window_size

        self.factory.send_next_event_to_connection(self)

    def _handle_stop_stream_request(self) -> None:
        if not self._stream_is_active:
            raise InvalidRequestError(InvalidRequestType.STREAM_IS_INACTIVE)

        self._stream_is_active = False

    def _validate_ack(self, ack_event_id: Optional[int]) -> None:
        """Validates an ack_event_id from a request.

        The ack_event_id can't be smaller than the last ack we've received
        and can't be larger than the last event we've sent.
        """
        if self._ack_event_id is not None and (
            ack_event_id is None or ack_event_id < self._ack_event_id
        ):
            raise InvalidRequestError(InvalidRequestType.ACK_TOO_SMALL)

        if ack_event_id is not None and (
            self._last_sent_event_id is None or self._last_sent_event_id < ack_event_id
        ):
            raise InvalidRequestError(InvalidRequestType.ACK_TOO_LARGE)

    def send_event_response(self, event_response: EventResponse) -> None:
        self._send_response(event_response)
        self._last_sent_event_id = event_response.event.id

    def send_invalid_request_response(
        self,
        _type: InvalidRequestType,
        invalid_payload: Optional[bytes] = None,
        error_message: Optional[str] = None
    ) -> None:
        invalid_request = None if invalid_payload is None else invalid_payload.decode('utf8')
        response = InvalidRequestResponse(
            type=_type,
            invalid_request=invalid_request,
            error_message=error_message
        )

        self._send_response(response)

    def _send_response(self, response: Response) -> None:
        payload = json_dumpb(response.dict())

        return self.sendMessage(payload)  # TODO: Error handling


class InvalidRequestError(Exception):
    def __init__(self, _type: InvalidRequestType):
        self.type = _type
