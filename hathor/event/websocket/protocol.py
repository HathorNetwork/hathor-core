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

from hathor.event.websocket.request import RequestWrapper

if TYPE_CHECKING:
    from hathor.event.websocket import EventWebsocketFactory

logger = get_logger()


class EventWebsocketProtocol(WebSocketServerProtocol):
    """ Websocket protocol, basically forwards some events to the Websocket factory.
    """

    factory: EventWebsocketFactory
    client_peer: Optional[str] = None
    last_sent_event_id: Optional[int] = None
    ack_event_id: Optional[int] = None
    window_size: int = 0
    streaming_is_active: bool = False

    def can_receive_event(self, event_id: int) -> bool:
        """Returns whether this client is available to receive an event."""
        number_of_pending_events = 0

        if self.last_sent_event_id is not None:
            ack_offset = -1 if self.ack_event_id is None else self.ack_event_id
            number_of_pending_events = self.last_sent_event_id - ack_offset

        return (
            self.streaming_is_active
            and event_id == self.next_expected_event_id()
            and number_of_pending_events < self.window_size
        )

    def next_expected_event_id(self) -> int:
        """Returns the ID of the next event the client expects."""
        return 0 if self.last_sent_event_id is None else self.last_sent_event_id + 1

    def __init__(self):
        super().__init__()
        self.log = logger.new()

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
            request = RequestWrapper.parse_raw(payload).__root__
            self.factory.handle_valid_request(self, request)
        except ValidationError as error:
            self.factory.handle_invalid_request(self, error)
