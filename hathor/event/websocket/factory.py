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
from typing import Set

from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger

from hathor.event import BaseEvent
from hathor.event.storage import EventStorage
from hathor.event.websocket.protocol import HathorEventWebsocketProtocol
from hathor.event.websocket.request import Request, RequestType, RequestError
from hathor.event.websocket.response import Response, ResponseType, NewEventResponseData, StopStreamingResponseData, \
    SpecificEventResponseData
from hathor.util import json_dumpb

logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = HathorEventWebsocketProtocol
    _is_running = False
    _connections: Set[HathorEventWebsocketProtocol] = set()

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
        response = Response(
            type=ResponseType.EVENT,
            data=NewEventResponseData(event)
        )
        payload = self._dataclass_to_payload(response)

        for connection in self._connections:
            if connection.streaming_is_active:
                connection.sendMessage(payload)
                connection.update_last_sent_event_id(event.id)

    def on_client_close(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        self._connections.discard(connection)

    def on_client_open(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        if not self._is_running:
            # TODO: Rejecting a connection should send something to the client
            return

        self._connections.add(connection)

    def handle_request_error(self, connection: HathorEventWebsocketProtocol, error: RequestError) -> None:
        payload = self._dataclass_to_payload(error)
        connection.sendMessage(payload)

    def handle_request(self, connection: HathorEventWebsocketProtocol, request: Request) -> None:
        match request.type:
            case RequestType.START_STREAMING_EVENTS:
                self._handle_start_streaming_events(connection, request.event_id)
            case RequestType.STOP_STREAMING_EVENTS:
                self._handle_stop_streaming_events(connection)
            case RequestType.GET_EVENT:
                self._handle_get_event(connection, request.event_id)

    def _handle_start_streaming_events(self, connection: HathorEventWebsocketProtocol, from_event_id: int) -> None:
        connection.streaming_is_active = True

        response = Response(ResponseType.START_STREAMING_EVENTS)
        payload = self._dataclass_to_payload(response)

        connection.sendMessage(payload)

        self._backfill_events(connection, from_event_id)

    def _backfill_events(self, connection: HathorEventWebsocketProtocol, from_event_id: int) -> None:
        # TODO: Limit number of events sent?
        events = self._event_storage.iter_from_event(from_event_id)

        for event in events:
            response = Response(
                type=ResponseType.EVENT,
                data=NewEventResponseData(event)
            )
            payload = self._dataclass_to_payload(response)

            connection.sendMessage(payload)
            connection.update_last_sent_event_id(event.id)

    def _handle_stop_streaming_events(self, connection: HathorEventWebsocketProtocol) -> None:
        connection.streaming_is_active = False

        response = Response(
            type=ResponseType.STOP_STREAMING_EVENTS,
            data=StopStreamingResponseData(connection.last_sent_event_id)
        )

        payload = self._dataclass_to_payload(response)

        connection.sendMessage(payload)

    def _handle_get_event(self, connection: HathorEventWebsocketProtocol, event_id: int) -> None:
        event = self._event_storage.get_event(event_id)
        response = Response(
            type=ResponseType.GET_EVENT,
            data=SpecificEventResponseData(event_id, event)
        )

        payload = self._dataclass_to_payload(response)

        connection.sendMessage(payload)

    @staticmethod
    def _dataclass_to_payload(obj: dataclass) -> bytes:
        return json_dumpb(asdict(obj))
