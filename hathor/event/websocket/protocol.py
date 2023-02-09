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
from hathor.event.websocket.response import InvalidRequestResponse, StreamIsActiveResponse, StreamIsInactiveResponse, \
    Response
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.event.websocket import EventWebsocketFactory

logger = get_logger()


class EventWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol, basically forwards some events to the Websocket factory.
    """

    factory: EventWebsocketFactory
    client_peer: Optional[str] = None

    last_sent_event_id: Optional[int] = None  # TODO: Make private
    _ack_event_id: Optional[int] = None
    _window_size: int = 0
    _stream_is_active: bool = False

    def __init__(self):
        super().__init__()
        self.log = logger.new()

    def can_receive_event(self, event_id: int) -> bool:
        """Returns whether this client is available to receive an event."""
        number_of_pending_events = 0

        if self.last_sent_event_id is not None:
            ack_offset = -1 if self._ack_event_id is None else self._ack_event_id
            number_of_pending_events = self.last_sent_event_id - ack_offset

        return (
            self._stream_is_active
            and event_id == self.next_expected_event_id()
            and number_of_pending_events < self._window_size
        )

    def next_expected_event_id(self) -> int:
        """Returns the ID of the next event the client expects."""
        return 0 if self.last_sent_event_id is None else self.last_sent_event_id + 1

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
            invalid_request = payload.decode('utf8')
            self._handle_invalid_request(invalid_request, error)

    def _handle_request(self, request: Request) -> None:
        match request:
            case StartStreamRequest():
                self._handle_start_stream_request(request)
            case AckRequest():
                self._handle_ack_request(request)
            case StopStreamRequest():
                self._handle_stop_stream_request()

    def _handle_invalid_request(self, invalid_request: str, validation_error: ValidationError) -> None:
        response = InvalidRequestResponse(
            invalid_request=invalid_request,
            errors=validation_error.errors()
        )

        self.send_response(response)

    def _handle_start_stream_request(self, request: StartStreamRequest) -> None:
        if self._stream_is_active:
            return self.send_response(StreamIsActiveResponse())

        self._validate_ack(request.last_ack_event_id)

        self.last_sent_event_id = request.last_ack_event_id
        self._ack_event_id = request.last_ack_event_id
        self._window_size = request.window_size
        self._stream_is_active = True

        self._send_next_event_to_connection(self)

    def _handle_ack_request(self, request: AckRequest) -> None:
        if not self._stream_is_active:
            return self.send_response(StreamIsInactiveResponse())

        self._validate_ack(request.ack_event_id)

        self._ack_event_id = request.ack_event_id
        self._window_size = request.window_size

        self._send_next_event_to_connection(self)

    def _handle_stop_stream_request(self) -> None:
        if not self._stream_is_active:
            return self.send_response(StreamIsInactiveResponse())

        self._stream_is_active = False

    def _validate_ack(self, ack_event_id: int) -> None:
        if ack_event_id < self._ack_event_id:
            raise  # TODO

        if ack_event_id > self.last_sent_event_id:
            raise  # TODO

    def send_response(self, response: Response) -> None:
        payload = json_dumpb(response.dict())

        return self.sendMessage(payload)  # TODO: Error handling
