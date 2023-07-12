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

from hathor.event.model.base_event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.protocol import EventWebsocketProtocol
from hathor.event.websocket.response import EventResponse, InvalidRequestType
from hathor.util import Reactor

logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """WebSocket factory that handles the broadcasting of the Event Queue feature."""

    protocol = EventWebsocketProtocol

    # Whether the factory is running or not.
    _is_running = False

    # The last event id broadcast by this factory.
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
        assert self._is_running is False, 'Cannot start, EventWebsocketFactory is already running'

        self._is_running = True

    def stop(self):
        """Stop the WebSocket server. No events can be sent."""
        assert self._is_running is True, 'Cannot stop, EventWebsocketFactory is not running'

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
            return connection.send_invalid_request_response(InvalidRequestType.EVENT_WS_NOT_RUNNING)

        self.log.info('registering connection', client_peer=connection.client_peer)

        self._connections.add(connection)

    def unregister(self, connection: EventWebsocketProtocol) -> None:
        """Unregisters a client. Called when a ws connection is closed."""
        self.log.info('unregistering connection', client_peer=connection.client_peer)
        self._connections.discard(connection)

    def send_next_event_to_connection(self, connection: EventWebsocketProtocol) -> None:
        """
        Sends the next expected event to a connection, if it can receive the next event, and the event exists.
        Will recurse asynchronously trying to send new events to the connection until it cannot receive more events.
        """
        next_event_id = connection.next_expected_event_id()

        if not connection.can_receive_event(next_event_id):
            return

        if event := self._event_storage.get_event(next_event_id):
            self._send_event_to_connection(connection, event)
            self._reactor.callLater(0, self.send_next_event_to_connection, connection)

    def _send_event_to_connection(self, connection: EventWebsocketProtocol, event: BaseEvent) -> None:
        """Sends an event to a connection, if it can receive this event."""
        if not connection.can_receive_event(event.id):
            return

        assert self._latest_event_id is not None, '_latest_event_id must be set.'

        response = EventResponse(event=event, latest_event_id=self._latest_event_id)

        connection.send_event_response(response)
