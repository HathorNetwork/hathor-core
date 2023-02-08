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
from hathor.event.websocket.request import AckRequest, Request, StartStreamRequest, StopStreamRequest
from hathor.event.websocket.response import BadRequestResponse, EventResponse, EventWebSocketNotRunningResponse
from hathor.util import Reactor, json_dumpb

logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = EventWebsocketProtocol
    _is_running = False
    _latest_event_id: Optional[int] = None

    def __init__(self, reactor: Reactor, event_storage: EventStorage):
        super().__init__()
        self.log = logger.new()
        self._reactor = reactor
        self._event_storage = event_storage
        self._connections: Set[EventWebsocketProtocol] = set()

        latest_event = self._event_storage.get_last_event()

        if latest_event is not None:
            self._latest_event_id = latest_event.id

    def start(self):
        """Start the WebSocket server. Required to be able to send events."""
        self._is_running = True

    def stop(self):
        """Stop the WebSocket server. No events can be sent."""
        self._is_running = False

        for connection in self._connections:
            connection.sendClose()

        self._connections.clear()

    def broadcast_event(self, event: BaseEvent) -> None:
        """Broadcast the event to each registered client."""
        self._latest_event_id = event.id

        for connection in self._connections:
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

    def handle_valid_request(self, connection: EventWebsocketProtocol, request: Request) -> None:
        """Handle a valid client request."""
        match request:
            case StartStreamRequest():
                self.handle_start_stream_request(connection, request)
            case AckRequest():
                self.handle_ack_request(connection, request)
            case StopStreamRequest():
                self.handle_stop_stream_request(connection)

    @staticmethod
    def handle_invalid_request(connection: EventWebsocketProtocol, validation_error: ValidationError) -> None:
        """Handle an invalid client request."""
        response = BadRequestResponse(errors=validation_error.errors())
        payload = json_dumpb(response.dict())

        connection.sendMessage(payload)  # TODO: Error handling

    def handle_start_stream_request(self, connection: EventWebsocketProtocol, request: StartStreamRequest) -> None:
        connection.last_sent_event_id = request.last_ack_event_id
        connection.ack_event_id = request.last_ack_event_id
        connection.window_size = request.window_size
        connection.streaming_is_active = True

        self._send_next_event_to_connection(connection)

    def handle_ack_request(self, connection: EventWebsocketProtocol, request: AckRequest) -> None:
        connection.ack_event_id = request.ack_event_id
        connection.window_size = request.window_size

        self._send_next_event_to_connection(connection)

    @staticmethod
    def handle_stop_stream_request(connection: EventWebsocketProtocol) -> None:
        connection.streaming_is_active = False

    def _send_next_event_to_connection(self, connection: EventWebsocketProtocol) -> None:
        next_event_id = connection.next_expected_event_id()

        if not connection.can_receive_event(next_event_id):
            return

        if event := self._event_storage.get_event(next_event_id):
            self._send_event_to_connection(connection, event)
            self._reactor.callLater(0, self._send_next_event_to_connection, connection)

    def _send_event_to_connection(self, connection: EventWebsocketProtocol, event: BaseEvent) -> None:
        if not connection.can_receive_event(event.id):
            return

        response = EventResponse(event=event, latest_event_id=self._latest_event_id)
        payload = json_dumpb(response.dict())

        connection.sendMessage(payload)  # TODO: Error handling
        connection.last_sent_event_id = event.id
