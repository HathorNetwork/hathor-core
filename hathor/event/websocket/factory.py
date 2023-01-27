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

from dataclasses import asdict, dataclass
from typing import Set, Optional, List

from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger

from hathor.event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.protocol import HathorEventWebsocketProtocol
from hathor.event.websocket.request import Request, RequestType, RequestError
from hathor.event.websocket.response import Response
from hathor.util import json_dumpb
from hathor.conf import HathorSettings

logger = get_logger()
settings = HathorSettings()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = HathorEventWebsocketProtocol
    _is_running = False
    _connections: Set[HathorEventWebsocketProtocol] = set()
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
            if connection.streaming_is_active:
                events = self._get_events_to_send(connection, event)
                response = Response(events, self._latest_event_id)
                payload = self._dataclass_to_payload(response)

                connection.sendMessage(payload)

    def _get_events_to_send(self, connection: HathorEventWebsocketProtocol, event: BaseEvent) -> List[BaseEvent]:
        next_event_id = connection.last_received_event_id + 1
        assert event.id >= next_event_id, 'Cannot reprocess past event.'

        if event.id == next_event_id:
            return [event]

        events = self._event_storage.iter_events(next_event_id, settings.EVENT_WS_MAX_BATCH_SIZE)

        # TODO: Change iter_events to list
        return list(events)

    def register(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        if not self._is_running:
            # TODO: Rejecting a connection should send something to the client
            return

        self._connections.add(connection)

    def unregister(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        self._connections.discard(connection)

    def handle_request_error(self, connection: HathorEventWebsocketProtocol, error: RequestError) -> None:
        payload = self._dataclass_to_payload(error)
        connection.sendMessage(payload)

    def handle_request(self, connection: HathorEventWebsocketProtocol, request: Request) -> None:
        match request.type:
            case RequestType.START_STREAMING_EVENTS:
                self._handle_start_streaming_events(connection, request.last_received_event_id)
            case RequestType.STOP_STREAMING_EVENTS:
                self._handle_stop_streaming_events(connection)

    @staticmethod
    def _handle_start_streaming_events(connection: HathorEventWebsocketProtocol, last_received_event_id: int) -> None:
        connection.last_received_event_id = last_received_event_id
        connection.streaming_is_active = True

    @staticmethod
    def _handle_stop_streaming_events(connection: HathorEventWebsocketProtocol) -> None:
        connection.streaming_is_active = False

    @staticmethod
    def _dataclass_to_payload(obj: dataclass) -> bytes:
        return json_dumpb(asdict(obj))
