from typing import Dict, Set
from uuid import uuid4

from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger
from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.event import BaseEvent
from hathor.event.websocket.protocol import HathorEventWebsocketProtocol
from hathor.util import json_dumpb, json_loadb, reactor

settings = HathorSettings()
logger = get_logger()


class EventWebsocketFactory(WebSocketServerFactory):
    """ Websocket that will handle events
    """

    protocol = HathorEventWebsocketProtocol

    def buildProtocol(self, address: str):
        return self.protocol(self)

    def __init__(self, event_storage):
        super().__init__()
        self.log = logger.new()
        self.is_running = False
        self.event_storage = event_storage

        # A timer to periodically send new events to clients that sent start_streaming_events message
        self._lc_send_events = LoopingCall(self._send_events_to_subscribed_clients)
        self._lc_send_events.clock = reactor

    def start(self):
        self.is_running = True

        # Start event sender
        self._lc_send_events.start(settings.WS_SEND_EVENTS_INTERVAL, now=False)

    def stop(self):
        self.is_running = False

        if self._lc_send_events.running:
            self._lc_send_events.stop()

    def on_new_event(self, event: BaseEvent) -> None:
        """Called when there is a new event, only after subscribing."""
        pass

    def on_client_close(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        # A connection closed before finishing handshake will not be in `self.connections`.
        self.connections.discard(connection)
        del self.connections_to_stream_events[connection.id]

    def on_client_open(self, connection: HathorEventWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        connection.id = str(uuid4())
        self.connections.add(connection)

    def handle_message(self, connection: HathorEventWebsocketProtocol, data: bytes) -> None:
        message = json_loadb(data)
        if message['type'] == 'start_streaming_events':
            self._handle_start_streaming_events(connection, message)
        elif message['type'] == 'stop_streaming_events':
            self._handle_stop_streaming_events(connection, message)
        elif message['type'] == 'get_event':
            self._handle_get_event(connection, message)

    def _handle_start_streaming_events(self, connection: HathorEventWebsocketProtocol, message: Dict) -> None:
        response = {'type': 'start_streaming_events', 'success': True}
        event_id = message['event_id'] if 'event_id' in message else 0

        if not event_id.isdigit():
            response['success'] = False
            response['reason'] = 'event_id must be a positive integer number'
        # else:
        #     self.connections_to_stream_events[connection.id] = EventStreaming(connection, event_id)

        payload = json_dumpb(response)
        connection.sendMessage(payload, False)

    def _handle_stop_streaming_events(self, connection: HathorEventWebsocketProtocol, message: Dict) -> None:
        self.connections_to_stream_events.pop(connection.id)
        del self.connections_to_stream_events[connection.id]
        payload = json_dumpb({'type': 'stop_streaming_events', 'success': True})
        connection.sendMessage(payload, False)

    def _handle_get_event(self, connection: HathorEventWebsocketProtocol, message: Dict) -> None:
        pass

    def _send_events_to_subscribed_clients(self) -> None:
        max_count = 100
        for event_streaming in self.connections_to_stream_events.values():
            iter_events = self.event_storage.iter_from_event(event_streaming.last_event)
            for i, event in enumerate(iter_events):
                if i == max_count:
                    break
                payload = json_dumpb({'type': 'event', 'data': event.__dict__})
                event_streaming.connection.sendMessage(payload)
