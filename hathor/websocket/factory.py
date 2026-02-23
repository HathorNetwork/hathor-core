# Copyright 2021 Hathor Labs
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

from collections import defaultdict, deque
from typing import Any, Optional

from autobahn.exception import Disconnected
from autobahn.twisted.websocket import WebSocketServerFactory
from structlog import get_logger
from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.indexes import AddressIndex
from hathor.manager import HathorManager
from hathor.metrics import Metrics
from hathor.p2p.rate_limiter import RateLimiter
from hathor.pubsub import EventArguments, HathorEvents
from hathor.reactor import get_global_reactor
from hathor.util import json_dumpb
from hathor.websocket.protocol import HathorAdminWebsocketProtocol

settings = HathorSettings()
logger = get_logger()

# CONTROLLED_TYPES define each Rate Limit parameter for each message type that should be limited
# buffer_size (int): size of the deque that will hold the messages that will be processed in the future
# time_buffering (int): Interval that we will try to process the deque with unprocessed messages
# max_hits (int) and hits_window_seconds (int): together they define the Rate Limit
# It's how many hits can this message make in the window interval

CONTROLLED_TYPES: dict[str, dict[str, Any]] = {
    HathorEvents.NETWORK_NEW_TX_ACCEPTED.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 20,
        'hits_window_seconds': 2,
    },
    HathorEvents.WALLET_OUTPUT_RECEIVED.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 10,
        'hits_window_seconds': 2,
    },
    HathorEvents.WALLET_INPUT_SPENT.value: {
        'buffer_size': 20,
        'time_buffering': 0.1,
        'max_hits': 10,
        'hits_window_seconds': 2,
    },
    HathorEvents.WALLET_BALANCE_UPDATED.value: {
        'buffer_size': 3,
        'time_buffering': 0.4,
        'max_hits': 3,
        'hits_window_seconds': 1,
    }
}

# these events should only be sent to websockets subscribed to a specific address, not broadcast
ADDRESS_EVENTS = [
    HathorEvents.WALLET_ADDRESS_HISTORY.value,
    HathorEvents.WALLET_ELEMENT_WINNER.value,
    HathorEvents.WALLET_ELEMENT_VOIDED.value
]


class HathorAdminWebsocketFactory(WebSocketServerFactory):
    """ Factory of the admin websocket protocol so we can subscribe to events and
        send messages in the Admin page to clients when the events are published
    """
    protocol = HathorAdminWebsocketProtocol

    max_subs_addrs_conn: Optional[int] = settings.WS_MAX_SUBS_ADDRS_CONN
    max_subs_addrs_empty: Optional[int] = settings.WS_MAX_SUBS_ADDRS_EMPTY

    def buildProtocol(self, addr):
        return self.protocol(self, is_history_streaming_enabled=self.is_history_streaming_enabled)

    def __init__(self,
                 manager: HathorManager,
                 metrics: Optional[Metrics] = None,
                 address_index: Optional[AddressIndex] = None):
        """
        :param metrics: If not given, a new one is created.
        :type metrics: :py:class:`hathor.metrics.Metrics`
        """
        self.manager = manager
        self.reactor = get_global_reactor()
        # Opened websocket connections so I can broadcast messages later
        # It contains only connections that have finished handshaking.
        self.connections: set[HathorAdminWebsocketProtocol] = set()

        # Enable/disable history streaming over the websocket connection.
        self.is_history_streaming_enabled: bool = True

        # Websocket connection for each address
        self.address_connections: defaultdict[str, set[HathorAdminWebsocketProtocol]] = defaultdict(set)
        super().__init__()

        # Limit the send message rate for specific type of data
        self.rate_limiter = RateLimiter(reactor=self.reactor)
        # Stores the buffer of messages that exceeded the rate limit and will be sent
        self.buffer_deques: dict[str, deque[dict[str, Any]]] = {}

        self.metrics = metrics
        self.address_index = address_index

        self.is_running = False

        self.log = logger.new()

        # A timer to periodically broadcast dashboard metrics
        self._lc_send_metrics = LoopingCall(self._send_metrics)
        self._lc_send_metrics.clock = self.reactor

    def start(self):
        self.is_running = True

        # Start limiter
        self._setup_rate_limit()

        # Start metric sender
        self._lc_send_metrics.start(settings.WS_SEND_METRICS_INTERVAL, now=False)

    def stop(self):
        if self._lc_send_metrics.running:
            self._lc_send_metrics.stop()
        self.is_running = False

    def disable_history_streaming(self) -> None:
        """Disable history streaming for all connections."""
        self.is_history_streaming_enabled = False
        for conn in self.connections:
            conn.disable_history_streaming()

    def _setup_rate_limit(self):
        """ Set the limit of the RateLimiter and start the buffer deques with BUFFER_SIZE
        """
        for control_type, config in CONTROLLED_TYPES.items():
            self.rate_limiter.set_limit(control_type, config['max_hits'], config['hits_window_seconds'])
            self.buffer_deques[control_type] = deque(maxlen=config['buffer_size'])

    def _send_metrics(self):
        """ Broadcast dashboard metric to websocket clients
        """
        self.broadcast_message({
            'transactions': self.metrics.transactions,
            'blocks': self.metrics.blocks,
            'best_block_height': self.metrics.best_block_height,
            'hash_rate': self.metrics.hash_rate,
            'peers': self.metrics.ready_peers,
            'type': 'dashboard:metrics',
            'time': self.reactor.seconds(),
        })

    def subscribe(self, pubsub):
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.WALLET_OUTPUT_RECEIVED,
            HathorEvents.WALLET_INPUT_SPENT,
            HathorEvents.WALLET_BALANCE_UPDATED,
            HathorEvents.WALLET_KEYS_GENERATED,
            HathorEvents.WALLET_GAP_LIMIT,
            HathorEvents.WALLET_HISTORY_UPDATED,
            HathorEvents.WALLET_ADDRESS_HISTORY,
            HathorEvents.WALLET_ELEMENT_WINNER,
            HathorEvents.WALLET_ELEMENT_VOIDED,
        ]

        for event in events:
            pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key, args):
        """ This method is called when pubsub publishes an event that we subscribed
            Then we broadcast the data to all connected clients
        """
        data = self.serialize_message_data(key, args)
        data['type'] = key.value
        self.send_or_enqueue(data)

    def serialize_message_data(self, event: HathorEvents, args: EventArguments) -> dict[str, Any]:
        """ Receives the event and the args from the pubsub
            and serializes the data so it can be passed in the websocket
        """
        # Ready events don't need extra serialization
        ready_events = [
            HathorEvents.WALLET_KEYS_GENERATED,
            HathorEvents.WALLET_GAP_LIMIT,
            HathorEvents.WALLET_HISTORY_UPDATED,
            HathorEvents.WALLET_ADDRESS_HISTORY,
        ]
        data = args.__dict__
        if event in ready_events:
            return data
        elif event == HathorEvents.WALLET_OUTPUT_RECEIVED:
            data['output'] = data['output'].to_dict()
            return data
        elif event == HathorEvents.WALLET_INPUT_SPENT:
            data['output_spent'] = data['output_spent'].to_dict()
            return data
        elif event == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            tx = data['tx']
            data = tx.to_json_extended()
            data['is_block'] = tx.is_block
            # needed to check if the transaction is from the mempool
            first_block = tx.get_metadata().first_block
            first_block_hex: Optional[str] = None if first_block is None else first_block.hex()
            data['first_block'] = first_block_hex
            return data
        elif event == HathorEvents.WALLET_BALANCE_UPDATED:
            data['balance'] = data['balance'][settings.HATHOR_TOKEN_UID]._asdict()
            return data
        else:
            raise ValueError('Should never have entered here! We dont know this event')

    def execute_send(self, data: dict[str, Any], connections: set[HathorAdminWebsocketProtocol]) -> None:
        """ Send data in ws message for the connections
        """
        try:
            payload = json_dumpb(data)
        except TypeError:
            self.log.error('failed to serialize data', data=repr(data), exc_info=True)
            return
        for c in connections:
            try:
                c.sendMessage(payload, False)
            except Disconnected:
                # Connection is closed. Nothing to do.
                pass
            # XXX: unfortunately autobahn can raise 3 different exceptions and one of them is a bare Exception
            # https://github.com/crossbario/autobahn-python/blob/v20.12.3/autobahn/websocket/protocol.py#L2201-L2294
            except Exception:
                self.log.error('send failed, moving on', exc_info=True)

    def broadcast_message(self, data: dict[str, Any]) -> None:
        """ Broadcast the update message to the connections
        """
        self.execute_send(data, self.connections)

    def send_message(self, data: dict[str, Any]) -> None:
        """ Check if should broadcast the message to all connections or send directly to some connections only
        """
        if data['type'] in ADDRESS_EVENTS:
            # This ws message will only be sent if the address was subscribed
            if data['address'] in self.address_connections:
                self.execute_send(data, self.address_connections[data['address']])
        else:
            self.broadcast_message(data)

    def send_or_enqueue(self, data):
        """ Try to broadcast the message, or enqueue it when rate limit is exceeded and we've been throttled.
            Enqueued messages are automatically sent after a while if they are not discarded first.
            A message is discarded when new messages arrive and the queue buffer is full.
            Rate limits change according to the message type, which is obtained from data['type'].

            :param data: message to be sent
            :type data: dict[string, X] -> X can be different types, depending on the type of message
        """
        if data['type'] in CONTROLLED_TYPES:
            # This type is controlled, so I need to check the deque
            if len(self.buffer_deques[data['type']]) or not self.rate_limiter.add_hit(data['type']):
                # If I am already with a buffer or if I hit the limit now, I enqueue for later
                self.enqueue_for_later(data)
            else:
                data['throttled'] = False
                self.send_message(data)
        else:
            self.send_message(data)

    def enqueue_for_later(self, data):
        """ Add this date to the correct deque to be processed later
            If this deque is not programed to be called later yet, we call it

            :param data: message to be sent
            :type data: dict[string, X] -> X can be different types, depending on the type of message
        """
        # Add data to deque
        # We always add the new messages in the end
        # Adding parameter deque=True, so the admin can know this message was delayed
        data['throttled'] = True
        self.buffer_deques[data['type']].append(data)
        if len(self.buffer_deques[data['type']]) == 1:
            # If it's the first time we hit the limit (only one message in deque), we schedule process_deque
            self.reactor.callLater(CONTROLLED_TYPES[data['type']]['time_buffering'], self.process_deque,
                                   data_type=data['type'])

    def process_deque(self, data_type):
        """ Process the deque and check if I have limit to send the messages now

            :param data_type: type of the message to be sent
            :type data_type: string
        """
        while len(self.buffer_deques[data_type]) > 0:
            if self.rate_limiter.add_hit(data_type):
                # We always process the older message first
                data = self.buffer_deques[data_type].popleft()
                if len(self.buffer_deques[data_type]) == 0:
                    data['throttled'] = False
                self.send_message(data)
            else:
                self.reactor.callLater(CONTROLLED_TYPES[data_type]['time_buffering'], self.process_deque,
                                       data_type=data_type)
                break

    def _handle_subscribe_address(self, connection: HathorAdminWebsocketProtocol, message: dict[Any, Any]) -> None:
        """ Handler for subscription to an address, consideirs subscription limits."""
        address: str = message['address']
        success, errmsg = self.subscribe_address(connection, address)
        response = {
            'type': 'subscribe_address',
            'address': address,
            'success': success,
        }
        if not success:
            response['message'] = errmsg
        connection.sendMessage(json_dumpb(response), False)

    def subscribe_address(self, connection: HathorAdminWebsocketProtocol, address: str) -> tuple[bool, str]:
        """Subscribe an address to send real time updates to a websocket connection."""
        subs: set[str] = connection.subscribed_to
        if self.max_subs_addrs_conn is not None and len(subs) >= self.max_subs_addrs_conn:
            return False, f'Reached maximum number of subscribed addresses ({self.max_subs_addrs_conn}).'

        empty_addresses: set[str] = connection.empty_addresses
        if (
            self.max_subs_addrs_empty is not None
            and self.address_index
            and len(empty_addresses) >= self.max_subs_addrs_empty
            and self._update_and_count_empty(empty_addresses) >= self.max_subs_addrs_empty
        ):
            return False, f'Reached maximum number of subscribed empty addresses ({self.max_subs_addrs_empty}).'

        self.address_connections[address].add(connection)
        connection.subscribed_to.add(address)
        if self.address_index and self.address_index.is_address_empty(address):
            connection.empty_addresses.add(address)
        return True, ''

    def _handle_unsubscribe_address(self, connection: HathorAdminWebsocketProtocol, message: dict[Any, Any]) -> None:
        """ Handler for unsubscribing from an address, also removes address connection set if it ends up empty."""
        addr = message['address']
        if addr in self.address_connections and connection in self.address_connections[addr]:
            connection.subscribed_to.remove(addr)
            connection.empty_addresses.discard(addr)
            self._remove_connection_from_address_dict(connection, addr)
            # Reply back to the client
            payload = json_dumpb({'type': 'unsubscribe_address', 'success': True})
            connection.sendMessage(payload, False)

    def _remove_connection_from_address_dict(self, connection: HathorAdminWebsocketProtocol, address: str) -> None:
        """ Remove a connection from the address connections dict
            If this was the last connection for this address, we remove the key
        """
        self.address_connections[address].remove(connection)
        # If this was the last connection for this address, we delete it from the dict
        if len(self.address_connections[address]) == 0:
            del self.address_connections[address]

    def on_client_open(self, connection: HathorAdminWebsocketProtocol) -> None:
        """Called when a ws connection is opened (after handshaking)."""
        self.connections.add(connection)

    def on_client_close(self, connection: HathorAdminWebsocketProtocol) -> None:
        """Called when a ws connection is closed."""
        # A connection closed before finishing handshake will not be in `self.connections`.
        self.connections.discard(connection)
        for address in connection.subscribed_to:
            self._remove_connection_from_address_dict(connection, address)

    def _update_and_count_empty(self, empty_addresses: set[str]) -> int:
        """Removes non-empty addresses from the given set and returns the updated count."""
        assert self.address_index is not None
        to_remove = set()
        for addr in empty_addresses:
            if not self.address_index.is_address_empty(addr):
                to_remove.add(addr)

        empty_addresses.difference_update(to_remove)
        return len(empty_addresses)
