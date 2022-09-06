from hathor.manager import HathorManager
from hathor.metrics import Metrics
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.pubsub import PubSubManager
from hathor.transaction.storage import TransactionCacheStorage, TransactionMemoryStorage
from hathor.util import reactor
from tests import unittest


class MetricsTest(unittest.TestCase):
    def test_peer_connections_data_collection(self):
        """Test if peer connections data is correctly being collected from the
            ConnectionsManager
        """
        # Preparation
        tx_storage = TransactionMemoryStorage(with_index=False)
        pubsub = PubSubManager(reactor)

        manager = HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub)

        my_peer = PeerId()

        def build_hathor_protocol():
            protocol = HathorProtocol(
                network="testnet",
                my_peer=my_peer,
                connections=manager.connections,
                node=manager,
                use_ssl=False,
                inbound=False
            )
            protocol.peer = PeerId()

            return protocol

        fake_peers = [
            build_hathor_protocol(),
            build_hathor_protocol(),
            build_hathor_protocol(),
        ]

        fake_peers[0].metrics.received_messages = 1
        fake_peers[0].metrics.received_bytes = 100
        fake_peers[0].metrics.received_txs = 1

        fake_peers[1].metrics.sent_messages = 2
        fake_peers[1].metrics.sent_bytes = 200

        fake_peers[2].metrics.discarded_blocks = 3
        fake_peers[2].metrics.discarded_txs = 3

        manager.connections.connections.add(fake_peers[0])
        manager.connections.connections.add(fake_peers[1])
        manager.connections.connections.add(fake_peers[2])

        # Execution
        manager.metrics._collect_data()

        # Assertion
        manager.metrics.peer_connection_metrics[0].received_messages = 1
        manager.metrics.peer_connection_metrics[0].received_bytes = 100
        manager.metrics.peer_connection_metrics[0].received_txs = 1
        manager.metrics.peer_connection_metrics[1].sent_messages = 2
        manager.metrics.peer_connection_metrics[1].sent_bytes = 200
        manager.metrics.peer_connection_metrics[2].discarded_blocks = 3
        manager.metrics.peer_connection_metrics[2].discarded_txs = 3

    def test_cache_data_collection(self):
        """Test if cache-related data is correctly being collected from the
            TransactionCacheStorage
        """
        # Preparation
        base_storage = TransactionMemoryStorage(with_index=False)
        tx_storage = TransactionCacheStorage(base_storage, reactor)
        pubsub = PubSubManager(reactor)

        manager = HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub)

        tx_storage.stats["hit"] = 10
        tx_storage.stats["miss"] = 20

        # Execution
        manager.metrics._collect_data()

        # Assertion
        self.assertEquals(manager.metrics.transaction_cache_hits, 10)
        self.assertEquals(manager.metrics.transaction_cache_misses, 20)
