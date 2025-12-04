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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple, Optional

from structlog import get_logger
from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.p2p.manager import ConnectionsManager, PeerConnectionsMetrics
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction.base_transaction import sum_weights
from hathor.transaction.block import Block
from hathor.transaction.storage import TransactionRocksDBStorage, TransactionStorage
from hathor.transaction.storage.cache_storage import TransactionCacheStorage

if TYPE_CHECKING:
    from hathor.stratum import StratumFactory  # noqa: F401
    from hathor.websocket.factory import HathorAdminWebsocketFactory  # noqa: F401

logger = get_logger()
settings = HathorSettings()


class WeightValue(NamedTuple):
    time: int
    value: float


@dataclass
class PeerConnectionMetrics:
    connection_string: str
    network: str
    peer_id: str
    received_messages: int = 0
    sent_messages: int = 0
    received_bytes: int = 0
    sent_bytes: int = 0
    received_txs: int = 0
    discarded_txs: int = 0
    received_blocks: int = 0
    discarded_blocks: int = 0


@dataclass
class Metrics:
    pubsub: PubSubManager
    avg_time_between_blocks: int
    connections: ConnectionsManager
    tx_storage: TransactionStorage
    # Twisted reactor that handles the time and callLater
    reactor: Reactor

    # Transactions count in the network
    transactions: int = 0
    # Blocks count in the network
    blocks: int = 0
    # Height of the best chain of the network
    best_block_height: int = 0
    # Hash rate of the network
    hash_rate: float = 0.0
    # Peers connected
    peers: int = 0
    # weight of the head of the best blockchain
    best_block_weight: float = 0
    # Length of the tx deque
    weight_tx_deque_len: int = 60
    # Length of the block deque
    weight_block_deque_len: int = 450
    # If metric capture data is running
    is_running: bool = False
    # Time between method call to collect data
    collect_data_interval: int = settings.METRICS_COLLECT_DATA_INTERVAL
    # Websocket data stored
    websocket_connections: int = 0
    subscribed_addresses: int = 0
    # Websocket factory
    websocket_factory: Optional['HathorAdminWebsocketFactory'] = None
    # Stratum data
    completed_jobs: int = 0
    blocks_found: int = 0
    estimated_hash_rate: float = 0  # log(H/s)
    stratum_factory: Optional['StratumFactory'] = None
    # Peer Connection data
    peer_connection_metrics: list[PeerConnectionMetrics] = field(default_factory=list)
    # Send-token timeouts counter
    send_token_timeouts: int = 0
    # Dict that stores the sizes of each column-family in RocksDB, in bytes
    rocksdb_cfs_sizes: dict[bytes, float] = field(default_factory=dict)
    # TxCache Data
    transaction_cache_hits: int = 0
    transaction_cache_misses: int = 0
    # The time interval to control periodic collection of RocksDB data
    txstorage_data_interval = settings.METRICS_COLLECT_ROCKSDB_DATA_INTERVAL
    # Variables to store the last block when we updated the RocksDB storage metrics
    last_txstorage_data_block: Optional[int] = None

    # Peers connected
    connected_peers: int = 0
    # Peers handshaking
    handshaking_peers: int = 0
    # Peers connecting
    connecting_peers: int = 0
    # Peers known
    known_peers: int = 0

    def __post_init__(self) -> None:
        self.log = logger.new()

        # Stores calculated tx weights saved in tx storage
        self.weight_tx_deque: deque[WeightValue] = deque(maxlen=self.weight_tx_deque_len)

        # Stores calculated block weights saved in tx storage
        self.weight_block_deque: deque[WeightValue] = deque(maxlen=self.weight_block_deque_len)

        # A timer to periodically collect data
        self._lc_collect_data = LoopingCall(self._collect_data)
        self._lc_collect_data.clock = self.reactor

        # The number of blocks interval to control periodic collection of RocksDB data
        # We use it instead of a time interval because it's better to make sure we update the
        # storage during sync.
        self.txstorage_data_block_interval = self.txstorage_data_interval / settings.AVG_TIME_BETWEEN_BLOCKS

    def _start_initial_values(self) -> None:
        """ When we start the metrics object we set the transaction and block count already in the network

            We also log some values that we just need to collect once, like the cache hits during initialization.
        """
        self.transactions = self.tx_storage.get_tx_count()
        self.blocks = self.tx_storage.get_block_count()

        (last_block, _) = self.tx_storage.get_newest_blocks(count=1)
        if last_block:
            self.hash_rate = self.calculate_new_hashrate(last_block[0])
            self.best_block_height = self.tx_storage.get_height_best_block()

        if isinstance(self.tx_storage, TransactionCacheStorage):
            self.log.info("Transaction cache hits during initialization", hits=self.tx_storage.stats.get("hit"))
            self.log.info("Transaction cache misses during initialization", misses=self.tx_storage.stats.get("miss"))

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
            HathorEvents.NETWORK_PEER_CONNECTING,
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
            HathorEvents.NETWORK_PEER_CONNECTING,
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
            assert self.websocket_factory.is_running, 'Websocket factory has not been started'

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

    def collect_peer_connection_metrics(self) -> None:
        """Collect metrics for each connected peer.
            The list is cleared every time to avoid memory leak.
        """
        self.peer_connection_metrics.clear()

        for connection in self.connections.connections:
            if not connection._peer:
                # A connection without peer will not be able to communicate
                # So we can just discard it for the sake of the metrics
                continue

            metric = PeerConnectionMetrics(
                connection_string=str(connection.entrypoint) if connection.entrypoint else "",
                peer_id=str(connection.peer.id),
                network=settings.NETWORK_NAME,
                received_messages=connection.metrics.received_messages,
                sent_messages=connection.metrics.sent_messages,
                received_bytes=connection.metrics.received_bytes,
                sent_bytes=connection.metrics.sent_bytes,
                received_txs=connection.metrics.received_txs,
                discarded_txs=connection.metrics.discarded_txs,
                received_blocks=connection.metrics.received_blocks,
                discarded_blocks=connection.metrics.discarded_blocks,
            )

            self.peer_connection_metrics.append(metric)

    def set_cache_data(self) -> None:
        """ Collect and set data related to the transactions cache.
        """
        if isinstance(self.tx_storage, TransactionCacheStorage):
            hits = self.tx_storage.stats.get("hit")
            misses = self.tx_storage.stats.get("miss")
            if hits:
                self.transaction_cache_hits = hits
            if misses:
                self.transaction_cache_misses = misses

    def set_tx_storage_data(self) -> None:
        store = self.tx_storage

        if isinstance(self.tx_storage, TransactionCacheStorage):
            store = self.tx_storage.store

        if not isinstance(store, TransactionRocksDBStorage):
            # We currently only collect metrics for RocksDB
            return

        best_block_count = self.tx_storage.get_height_best_block()

        if self.last_txstorage_data_block and (
            best_block_count - self.last_txstorage_data_block
        ) < self.txstorage_data_block_interval:
            return

        self.last_txstorage_data_block = best_block_count

        self.rocksdb_cfs_sizes = store.get_sst_files_sizes_by_cf()

    def _collect_data(self) -> None:
        """ Call methods that collect data to metrics
        """
        self.set_websocket_data()
        self.set_stratum_data()
        self.set_cache_data()
        self.collect_peer_connection_metrics()
        self.set_tx_storage_data()
