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
from pydantic import ValidationError
from structlog import get_logger

from hathor.event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.request import StreamRequest
from hathor.event.websocket.response import BadRequestResponse, EventResponse, EventWebSocketNotRunningResponse
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

        latest_event = self._event_storage.get_last_event()

        if latest_event is not None:
            self._latest_event_id = latest_event.id

    def start(self):
        """Start the WebSocket server. Required to be able to send events."""
        self.log.info('event websocket started')
        self._is_running = True

    def stop(self):
        """Stop the WebSocket server. No events can be sent."""
        self.log.info('event websocket stopped')
        self._is_running = False

        for connection in self._connections:
            connection.sendClose()

        self._connections = set()

    def broadcast_event(self, event: BaseEvent) -> None:
        """Broadcast the event to each registered client."""
        self._latest_event_id = event.id

        for connection in self._connections:
            if event.id == connection.next_event_id:
                self._send_event_to_connection(connection, event)

    def register(self, connection: EventWebsocketProtocol) -> None:
        """Registers a client. Called when a ws connection is opened (after handshaking)."""
        if not self._is_running:
            response = EventWebSocketNotRunningResponse().dict()
            payload = json_dumpb(response)

            return connection.sendMessage(payload)

        self.log.info('registering connection', client_peer=connection.client_peer)

        self._connections.add(connection)

    def unregister(self, connection: EventWebsocketProtocol) -> None:
        """Unregisters a client. Called when a ws connection is closed."""
        self.log.info('unregistering connection', client_peer=connection.client_peer)
        self._connections.discard(connection)

    def handle_valid_request(self, connection: EventWebsocketProtocol, request: StreamRequest) -> None:
        """Handle a valid client request."""
        connection.last_received_event_id = request.last_received_event_id
        connection.available_window_size += request.window_size_increment

        events = self._event_storage.iter_from_event(connection.next_event_id)

        for event in events:
            can_receive = self._send_event_to_connection(connection, event)

            if not can_receive:
                break

    @staticmethod
    def handle_invalid_request(connection: EventWebsocketProtocol, validation_error: ValidationError) -> None:
        """Handle an invalid client request."""
        response = BadRequestResponse(errors=validation_error.errors()).dict()
        payload = json_dumpb(response)

        connection.sendMessage(payload)

    def _send_event_to_connection(self, connection: EventWebsocketProtocol, event: BaseEvent) -> bool:
        if connection.available_window_size <= 0:
            return False

        response = EventResponse(
            event=event,
            latest_event_id=self._latest_event_id
        ).dict()
        payload = json_dumpb(response)

        connection.sendMessage(payload)
        connection.last_received_event_id = event.id
        connection.available_window_size -= 1

        return True
