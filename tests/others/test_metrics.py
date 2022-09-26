import tempfile
from unittest.mock import Mock

import pytest

from hathor.manager import HathorManager
from hathor.p2p.manager import PeerConnectionsMetrics
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.util import reactor
from hathor.wallet import Wallet
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import (
    TransactionCacheStorage,
    TransactionCompactStorage,
    TransactionMemoryStorage,
    TransactionRocksDBStorage,
)
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from tests import unittest
from tests.utils import HAS_ROCKSDB, add_new_blocks


class BaseMetricsTest(unittest.TestCase):
    __test__ = False

    def test_p2p_network_events(self):
        """Simulates publishing an event to pubsub the same way as done
           by the ConnectionsManager class.

           The expected result is that the Metrics class will use the info provided with
           the event to set its own fields related to the network peers
        """
        # Preparation
        tx_storage = TransactionMemoryStorage()
        pubsub = PubSubManager(reactor)
        manager = HathorManager(self.clock, tx_storage=tx_storage, pubsub=pubsub)

        manager.metrics.start()

        # Execution
        pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTED,
            protocol=Mock(),
            peers_count=PeerConnectionsMetrics(3, 4, 5, 6)
        )

        # Assertion
        self.assertEquals(manager.metrics.connecting_peers, 3)
        self.assertEquals(manager.metrics.handshaking_peers, 4)
        self.assertEquals(manager.metrics.connected_peers, 5)
        self.assertEquals(manager.metrics.known_peers, 6)

        manager.metrics.stop()

    def test_connections_manager_integration(self):
        """Tests the integration with the ConnectionsManager class

           The expected result is that the both classes communicate through pubsub
           to update the Metrics class with info from ConnectionsManager class
        """
        # Preparation
        tx_storage = TransactionMemoryStorage()
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)
        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'teste')
        manager = HathorManager(self.clock, tx_storage=tx_storage, wallet=wallet)

        manager.metrics.start()

        manager.connections.peer_storage.update({"1": Mock(), "2": Mock(), "3": Mock()})
        manager.connections.connected_peers.update({"1": Mock(), "2": Mock()})
        manager.connections.handshaking_peers.update({Mock()})

        # Execution
        endpoint = 'tcp://127.0.0.1:8005'
        # This will trigger sending to the pubsub one of the network events
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.run_to_completion()

        # Assertion
        self.assertEquals(manager.metrics.known_peers, 3)
        self.assertEquals(manager.metrics.connected_peers, 2)
        self.assertEquals(manager.metrics.handshaking_peers, 1)
        self.assertEquals(manager.metrics.connecting_peers, 0)

        manager.metrics.stop()

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_tx_storage_data_collection_with_rocksdb_storage_and_no_cache(self):
        """Tests storage data collection when using RocksDB Storage
           with cache disabled.

           The expected result is that it will successfully collect
           the RocksDB metrics.
        """
        reactor = self.clock

        path = tempfile.mkdtemp()
        self.tmpdirs.append(path)

        def _init_manager():
            rocksdb_storage = RocksDBStorage(path=path, cache_capacity=100)
            tx_storage = TransactionRocksDBStorage(rocksdb_storage,
                                                   with_index=True,
                                                   use_memory_indexes=True)

            pubsub = PubSubManager(reactor)
            wallet = self._create_test_wallet()
            return HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub, wallet=wallet)

        manager = _init_manager()
        manager.metrics._collect_data()

        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {
            b'default': 0.0,
            b'tx': 0.0,
            b'meta': 0.0,
            b'attr': 0.0
        })

        add_new_blocks(manager, 10)
        # XXX: I had to close the DB and reinitialize the classes to force a flush of RocksDB memtables to disk
        # But I think we could do this in a better way if we had a python-binding for this Flush method in
        # https://github.com/facebook/rocksdb/blob/v7.5.3/include/rocksdb/db.h#L1396
        manager.tx_storage._db.close()

        manager = _init_manager()
        manager.metrics._collect_data()

        # We don't know exactly the sizes of each column family,
        # but we know empirically that they should be higher than these values
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'tx'] > 500)
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'meta'] > 1000)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_tx_storage_data_collection_with_rocksdb_storage_and_cache(self):
        """Tests storage data collection when using RocksDB Storage
           with cache enabled.

           The expected result is that it will successfully collect
           the RocksDB metrics.
        """
        reactor = self.clock

        path = tempfile.mkdtemp()
        self.tmpdirs.append(path)

        def _init_manager():
            rocksdb_storage = RocksDBStorage(path=path, cache_capacity=100)
            tx_storage = TransactionRocksDBStorage(rocksdb_storage,
                                                   with_index=False,
                                                   use_memory_indexes=True)
            tx_storage = TransactionCacheStorage(tx_storage, reactor)

            pubsub = PubSubManager(reactor)
            wallet = self._create_test_wallet()
            return HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub, wallet=wallet)

        manager = _init_manager()
        manager.metrics._collect_data()

        # Assert that the metrics are really zero
        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {
            b'default': 0.0,
            b'tx': 0.0,
            b'meta': 0.0,
            b'attr': 0.0
        })

        manager.tx_storage.pre_init()
        manager.tx_storage.indexes._manually_initialize(manager.tx_storage)

        add_new_blocks(manager, 10)

        # XXX: I had to close the DB and reinitialize the classes to force a flush of RocksDB memtables to disk
        # But I think we could do this in a better way if we had a python-binding for this Flush method in
        # https://github.com/facebook/rocksdb/blob/v7.5.3/include/rocksdb/db.h#L1396
        manager.tx_storage.store._db.close()

        manager = _init_manager()
        manager.metrics._collect_data()

        # We don't know exactly the sizes of each column family,
        # but we know empirically that they should be higher than these values
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'tx'] > 500)
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'meta'] > 1000)

    def test_tx_storage_data_collection_with_compact_storage(self):
        """Tests storage data collection when using JSON Storage.
           We test it both with cache enabled and disabled.

           The expected result is that nothing is done, because we currently only collect
           data for RocksDB storage
        """
        reactor = self.clock

        path = tempfile.mkdtemp()
        self.tmpdirs.append(path)

        def _init_manager(cache_enabled: bool) -> HathorManager:
            tx_storage: BaseTransactionStorage = TransactionCompactStorage(path=path, with_index=(not cache_enabled))

            if cache_enabled:
                tx_storage = TransactionCacheStorage(tx_storage, reactor)

            pubsub = PubSubManager(reactor)
            wallet = self._create_test_wallet()
            return HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub, wallet=wallet)

        # With cache
        manager = _init_manager(cache_enabled=True)
        manager.metrics._collect_data()
        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {})

        # Without cache
        manager = _init_manager(cache_enabled=False)
        manager.metrics._collect_data()
        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {})

    def test_tx_storage_data_collection_with_memory_storage(self):
        """Tests storage data collection when using Memory Storage using no cache
           We don't allow using it with cache, so this is the only case

           The expected result is that nothing is done, because we currently only collect
           data for RocksDB storage
        """
        reactor = self.clock
        tx_storage = TransactionMemoryStorage()

        # All
        pubsub = PubSubManager(reactor)
        manager = HathorManager(reactor=reactor, tx_storage=tx_storage, pubsub=pubsub)

        manager.metrics._collect_data()

        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {})

    def test_peer_connections_data_collection(self):
        """Test if peer connections data is correctly being collected from the
            ConnectionsManager
        """
        # Preparation
        reactor = self.clock
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
        reactor = self.clock
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


class SyncV1MetricsTest(unittest.SyncV1Params, BaseMetricsTest):
    __test__ = True


class SyncV2MetricsTest(unittest.SyncV2Params, BaseMetricsTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeMetricsTest(unittest.SyncBridgeParams, SyncV2MetricsTest):
    pass