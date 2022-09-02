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

from collections import deque
from typing import TYPE_CHECKING, Deque, NamedTuple, Optional

from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.p2p.manager import PeerConnectionsMetrics
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.transaction.base_transaction import sum_weights
from hathor.transaction.block import Block
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.util import Reactor

if TYPE_CHECKING:
    from hathor.stratum import StratumFactory  # noqa: F401
    from hathor.websocket.factory import HathorAdminWebsocketFactory  # noqa: F401

settings = HathorSettings()


class WeightValue(NamedTuple):
    time: int
    value: float


class Metrics:
    transactions: int
    blocks: int
    best_block_height: int
    hash_rate: float
    connected_peers: int
    handshaking_peers: int
    connecting_peers: int
    known_peers: int
    tx_hash_rate: float
    block_hash_rate: float
    best_block_weight: float
    weight_tx_deque_len: int
    weight_block_deque_len: int
    weight_tx_deque: Deque[WeightValue]
    weight_block_deque: Deque[WeightValue]
    avg_time_between_blocks: int
    pubsub: PubSubManager
    tx_storage: TransactionStorage
    reactor: Reactor
    is_running: bool
    exponential_alfa: float  # XXX: "alpha"?
    tx_hash_store_interval: int
    block_hash_store_interval: int
    collect_data_interval: int
    websocket_connections: int
    subscribed_addresses: int
    websocket_factory: Optional['HathorAdminWebsocketFactory']
    completed_jobs: int
    blocks_found: int
    estimated_hash_rate: float  # log(H/s)
    stratum_factory: Optional['StratumFactory']
    send_token_timeouts: int

    def __init__(
            self,
            pubsub: PubSubManager,
            avg_time_between_blocks: int,
            tx_storage: Optional[TransactionStorage] = None,
            reactor: Optional[Reactor] = None,
    ):
        """
        :param pubsub: If not given, a new one is created.
        :param tx_storage: If not given, a new one is created.
        :param avg_time_between_blocks: Seconds between blocks (comes from manager)
        :param tx_storage: Transaction storage
        :param reactor: Twisted reactor that handles the time and callLater
        """
        # Transactions count in the network
        self.transactions = 0

        # Blocks count in the network
        self.blocks = 0

        # Height of the best chain of the network
        self.best_block_height = 0

        # Hash rate of the network
        self.hash_rate = 0.0

        # Peers connected
        self.connected_peers = 0

        # Peers connecting
        self.connecting_peers = 0

        # Peers handshaking
        self.handshaking_peers = 0

        # Peers known
        self.known_peers = 0

        # Hash rate of tx
        self.tx_hash_rate = 0.0

        # Hash rate of block
        self.block_hash_rate = 0

        # Length of the tx deque
        self.weight_tx_deque_len = 60

        # Length of the block deque
        self.weight_block_deque_len = 450

        # Stores caculated tx weights saved in tx storage
        self.weight_tx_deque = deque(maxlen=self.weight_tx_deque_len)

        # Stores caculated block weights saved in tx storage
        self.weight_block_deque = deque(maxlen=self.weight_block_deque_len)

        self.avg_time_between_blocks = avg_time_between_blocks

        self.pubsub = pubsub

        self.tx_storage = tx_storage or TransactionMemoryStorage()

        if reactor is None:
            from hathor.util import reactor as twisted_reactor
            reactor = twisted_reactor
        self.reactor = reactor

        # If metric capture data is running
        self.is_running = False

        # Coefficient of exponential calculus
        self.exponential_alfa = 0.7

        # Time between method call to store hash count
        self.tx_hash_store_interval = 1
        self.block_hash_store_interval = 1

        # Websocket data stored
        self.websocket_connections = 0
        self.subscribed_addresses = 0

        # Websocket factory
        self.websocket_factory = None

        # weight of the head of the best blockchain
        self.best_block_weight = 0

        # Stratum data
        self.completed_jobs = 0
        self.blocks_found = 0
        self.estimated_hash_rate = 0

        # Stratum factory
        self.stratum_factory = None

        # Send-token timeouts counter
        self.send_token_timeouts = 0

        # Time between method call to collect data
        self.collect_data_interval = settings.METRICS_COLLECT_DATA_INTERVAL

        # A timer to periodically collect data
        self._lc_collect_data = LoopingCall(self._collect_data)
        self._lc_collect_data.clock = reactor

    def _start_initial_values(self) -> None:
        """ When we start the metrics object we set the transaction and block count already in the network
        """
        self.transactions = self.tx_storage.get_tx_count()
        self.blocks = self.tx_storage.get_block_count()

        (last_block, _) = self.tx_storage.get_newest_blocks(count=1)
        if last_block:
            self.hash_rate = self.calculate_new_hashrate(last_block[0])
            self.best_block_height = self.tx_storage.get_height_best_block()

    def start(self) -> None:
        self._start_initial_values()
        self.subscribe()
        self.is_running = True
        self._lc_collect_data.start(self.collect_data_interval, now=False)

    def stop(self) -> None:
        self.is_running = False
        if self._lc_collect_data.running:
            self._lc_collect_data.stop()

    def subscribe(self) -> None:
        """ Subscribe to defined events for the pubsub received
        """
        events = [
            HathorEvents.NETWORK_NEW_TX_ACCEPTED,
            HathorEvents.NETWORK_PEER_READY,
            HathorEvents.NETWORK_PEER_CONNECTED,
            HathorEvents.NETWORK_PEER_DISCONNECTED,
            HathorEvents.NETWORK_PEER_CONNECTION_FAILED
        ]

        for event in events:
            self.pubsub.subscribe(event, self.handle_publish)

    def handle_publish(self, key: HathorEvents, args: EventArguments) -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        if key == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            if data['tx'].is_block:
                self.blocks = self.tx_storage.get_block_count()
                self.hash_rate = self.calculate_new_hashrate(data['tx'])
                self.best_block_weight = self.tx_storage.get_weight_best_block()
                self.best_block_height = self.tx_storage.get_height_best_block()
            else:
                self.transactions = self.tx_storage.get_tx_count()
        elif key in (
            HathorEvents.NETWORK_PEER_READY,
            HathorEvents.NETWORK_PEER_CONNECTED,
            HathorEvents.NETWORK_PEER_DISCONNECTED,
            HathorEvents.NETWORK_PEER_CONNECTION_FAILED
        ):
            peers_connection_metrics: PeerConnectionsMetrics = data["peers_count"]

            self.connected_peers = peers_connection_metrics.connected_peers_count
            self.connecting_peers = peers_connection_metrics.connecting_peers_count
            self.handshaking_peers = peers_connection_metrics.handshaking_peers_count
            self.known_peers = peers_connection_metrics.known_peers_count
        else:
            raise ValueError('Invalid key')

    def calculate_new_hashrate(self, block: Block) -> float:
        """ Weight formula: w = log2(avg_time_between_blocks) + log2(hash_rate)
        """
        from math import log
        return 2**(block.weight - log(self.avg_time_between_blocks, 2))

    def set_websocket_data(self) -> None:
        """ Set websocket metrics data. Connections and addresses subscribed.
        """
        if self.websocket_factory:
            self.websocket_connections = len(self.websocket_factory.connections)
            self.subscribed_addresses = len(self.websocket_factory.address_connections)

    def set_stratum_data(self) -> None:
        """ Set stratum metrics data for the mining process
        """
        if not self.stratum_factory:
            return

        stratum_stats = self.stratum_factory.get_stats()
        completed_jobs = 0
        blocks_found = 0
        estimated_hash_rate = 0.0
        for stats in stratum_stats:
            completed_jobs += stats.completed_jobs
            blocks_found += stats.blocks_found
            estimated_hash_rate = sum_weights(estimated_hash_rate, stats.estimated_hash_rate)

        self.completed_jobs = completed_jobs
        self.blocks_found = blocks_found
        self.estimated_hash_rate = estimated_hash_rate

    def _collect_data(self) -> None:
        """ Call methods that collect data to metrics
        """
        self.set_websocket_data()
        self.set_stratum_data()
