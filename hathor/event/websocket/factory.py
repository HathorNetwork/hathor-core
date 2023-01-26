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

from dataclasses import asdict
from typing import Set, Optional

from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger

from hathor.event import BaseEvent
from hathor.event.websocket.protocol import HathorEventWebsocketProtocol
from hathor.event.websocket.request import Request, RequestType
from hathor.event.websocket.response import Response, ResponseType, EventResponseData, StopStreamingResponseData
from hathor.util import json_dumpb

logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = HathorEventWebsocketProtocol
    _is_running = False
    _connections: Set[HathorEventWebsocketProtocol] = set()

    def __init__(self):
        super().__init__()
        self.log = logger.new()

    def start(self):
        self._is_running = True

    def stop(self):
        self._is_running = False

        for connection in self._connections:
            connection.sendClose()

        self._connections = set()

    def broadcast_event(self, event: BaseEvent) -> None:
        """Called when there is a new event, only after subscribing."""
        response = Response(
            type=ResponseType.NEW_EVENT,
            data=EventResponseData(event)
        )

        payload = json_dumpb(asdict(response))

        for connection in self._connections:
            if connection.streaming_is_active:
                connection.sendMessage(payload)

    def on_client_close(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        self._connections.discard(connection)

    def on_client_open(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        if not self._is_running:
            # TODO: Rejecting a connection should send something to the client
            return

        self._connections.add(connection)

    def handle_request(self, connection: HathorEventWebsocketProtocol, request: Request) -> None:
        match request.type:
            case RequestType.START_STREAMING_EVENTS:
                self._handle_start_streaming_events(connection, request.event_id)
            case RequestType.STOP_STREAMING_EVENTS:
                self._handle_stop_streaming_events(connection)
            case RequestType.GET_EVENT:
                self._handle_get_event(connection, request.event_id)

    @staticmethod
    def _handle_start_streaming_events(connection: HathorEventWebsocketProtocol, event_id: Optional[int]) -> None:
        # TODO: use event_id
        connection.streaming_is_active = True

        response = Response(ResponseType.START_STREAMING_EVENTS)
        payload = json_dumpb(asdict(response))

        connection.sendMessage(payload)

    @staticmethod
    def _handle_stop_streaming_events(connection: HathorEventWebsocketProtocol) -> None:
        connection.streaming_is_active = False

        response = Response(
            type=ResponseType.STOP_STREAMING_EVENTS,
            data=StopStreamingResponseData(None)  # TODO: put event_id
        )
        payload = json_dumpb(asdict(response))

        connection.sendMessage(payload)

    def _handle_get_event(self, connection: HathorEventWebsocketProtocol, event_id: int) -> None:
        # TODO: Get from event_storage?
        pass

    # def _send_events_to_subscribed_clients(self) -> None:
    #     max_count = 100
    #     for event_streaming in self.connections_to_stream_events.values():
    #         iter_events = self.event_storage.iter_from_event(event_streaming.last_event)
    #         for i, event in enumerate(iter_events):
    #             if i == max_count:
    #                 break
    #             payload = json_dumpb({'type': 'event', 'data': event.__dict__})
    #             event_streaming.connection.sendMessage(payload)
