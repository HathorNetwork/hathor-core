# Copyright 2023 Hathor Labs
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

from typing import Optional, Set

from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger

from hathor.event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.request import StreamRequest
from hathor.event.websocket.response import Response
from hathor.util import json_dumpb

logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = EventWebsocketProtocol
    _is_running = False
    _connections: Set[EventWebsocketProtocol] = set()
    _latest_event_id: Optional[int] = None

    def __init__(self, event_storage: EventStorage):
        super().__init__()
        self.log = logger.new()
        self._event_storage = event_storage

    def start(self):
        self._is_running = True

    def stop(self):
        self._is_running = False

        for connection in self._connections:
            connection.sendClose()

        self._connections = set()

    def broadcast_event(self, event: BaseEvent) -> None:
        """Called when there is a new event, only after subscribing."""
        self._latest_event_id = event.id

        for connection in self._connections:
            if event.id == connection.next_event_id:
                self._send_event_to_connection(connection, event)

    def register(self, connection: EventWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        if not self._is_running:
            # TODO: Rejecting a connection should send something to the client
            return

        self._connections.add(connection)

    def unregister(self, connection: EventWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        self._connections.discard(connection)

    def handle_request(self, connection: EventWebsocketProtocol, request: StreamRequest) -> None:
        connection.last_received_event_id = request.last_received_event_id
        connection.available_window_size += request.window_size_increment

        events = self._event_storage.iter_from_event(connection.next_event_id)

        for event in events:
            can_receive = self._send_event_to_connection(connection, event)

            if not can_receive:
                break

    def _send_event_to_connection(self, connection: EventWebsocketProtocol, event: BaseEvent) -> bool:
        if connection.available_window_size <= 0:
            return False

        response = Response(event=event, latest_event_id=self._latest_event_id).dict()
        payload = json_dumpb(response)

        connection.sendMessage(payload)
        connection.available_window_size -= 1

        return True
