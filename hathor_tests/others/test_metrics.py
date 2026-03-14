import tempfile
from unittest.mock import Mock

from hathor.indexes import RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.p2p.manager import PeerConnectionsMetrics
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerEndpoint
from hathor.p2p.protocol import HathorProtocol
from hathor.pubsub import HathorEvents
from hathor.simulator.utils import add_new_blocks
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.storage.rocksdb_storage import CacheConfig
from hathor.transaction.vertex_children import RocksDBVertexChildrenService
from hathor.transaction.vertex_parser import VertexParser
from hathor.wallet import Wallet
from hathor_tests import unittest


class MetricsTest(unittest.TestCase):
    def test_p2p_network_events(self):
        """Simulates publishing an event to pubsub the same way as done
           by the ConnectionsManager class.

           The expected result is that the Metrics class will use the info provided with
           the event to set its own fields related to the network peers
        """
        # Preparation
        manager = self.create_peer('testnet')
        pubsub = manager.pubsub

        # Execution
        pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTED,
            protocol=Mock(),
            peers_count=PeerConnectionsMetrics(3, 4, 5, 6)
        )
        self.run_to_completion()

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
        tx_storage = self.create_tx_storage()
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)
        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'teste')
        manager = self.create_peer('testnet', tx_storage=tx_storage, wallet=wallet)

        manager.connections.verified_peer_storage.update({
            "1": PrivatePeer.auto_generated(),
            "2": PrivatePeer.auto_generated(),
            "3": PrivatePeer.auto_generated(),
        })
        manager.connections.connected_peers.update({"1": Mock(), "2": Mock()})
        manager.connections.handshaking_peers.update({Mock()})

        # Execution
        endpoint = PeerEndpoint.parse('tcp://127.0.0.1:8005')
        # This will trigger sending to the pubsub one of the network events
        manager.connections.connect_to_endpoint(endpoint, use_ssl=True)

        self.run_to_completion()

        # Assertion
        self.assertEquals(manager.metrics.known_peers, 3)
        self.assertEquals(manager.metrics.connected_peers, 2)
        self.assertEquals(manager.metrics.handshaking_peers, 1)
        self.assertEquals(manager.metrics.connecting_peers, 1)

        manager.metrics.stop()

    def test_tx_storage_data_collection_with_rocksdb_storage_and_no_cache(self):
        """Tests storage data collection when using RocksDB Storage
           with cache disabled.

           The expected result is that it will successfully collect
           the RocksDB metrics.
        """
        def _init_manager(path: tempfile.TemporaryDirectory | None = None) -> HathorManager:
            builder = self.get_builder() \
                .set_rocksdb_cache_capacity(100) \
                .set_wallet(self._create_test_wallet(unlocked=True))
            if path:
                builder.set_rocksdb_path(path)
            manager = self.create_peer_from_builder(builder, start_manager=False)
            return manager

        manager = _init_manager()
        manager.metrics._collect_data()

        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {
            b'default': 0.0,
            b'tx': 0.0,
            b'meta': 0.0,
            b'attr': 0.0,
            b'migrations': 0.0,
            b'static-meta': 0.0,
            b'event': 0.0,
            b'event-metadata': 0.0,
            b'feature-activation-metadata': 0.0,
            b'info-index': 0.0,
            b'height-index': 0.0,
            b'timestamp-sorted-all': 0.0,
            b'timestamp-sorted-blocks': 0.0,
            b'timestamp-sorted-txs': 0.0,
            b'nc-state': 0.0,
            b'vertex-children': 0.0,
        })

        manager.tx_storage.pre_init()
        manager.tx_storage.indexes._manually_initialize(manager.tx_storage)

        add_new_blocks(manager, 10)
        # XXX: I had to close the DB and reinitialize the classes to force a flush of RocksDB memtables to disk
        # But I think we could do this in a better way if we had a python-binding for this Flush method in
        # https://github.com/facebook/rocksdb/blob/v7.5.3/include/rocksdb/db.h#L1396
        manager.tx_storage._db.close()

        manager = _init_manager(manager.tx_storage._rocksdb_storage.temp_dir)
        manager.metrics._collect_data()

        # We don't know exactly the sizes of each column family,
        # but we know empirically that they should be higher than these values
        self.assertGreater(manager.metrics.rocksdb_cfs_sizes[b'tx'], 500)
        self.assertGreater(manager.metrics.rocksdb_cfs_sizes[b'meta'], 1000)

    def test_tx_storage_data_collection_with_rocksdb_storage_and_cache(self):
        """Tests storage data collection when using RocksDB Storage
           with cache enabled.

           The expected result is that it will successfully collect
           the RocksDB metrics.
        """
        def _init_manager(path: tempfile.TemporaryDirectory | None = None) -> HathorManager:
            builder = self.get_builder() \
                .set_rocksdb_cache_capacity(100) \
                .set_wallet(self._create_test_wallet(unlocked=True)) \
                .use_tx_storage_cache()
            if path:
                builder.set_rocksdb_path(path)
            manager = self.create_peer_from_builder(builder, start_manager=False)
            return manager

        manager = _init_manager()
        manager.metrics._collect_data()

        # Assert that the metrics are really zero
        self.assertEqual(manager.metrics.rocksdb_cfs_sizes, {
            b'default': 0.0,
            b'tx': 0.0,
            b'meta': 0.0,
            b'attr': 0.0,
            b'migrations': 0.0,
            b'static-meta': 0.0,
            b'event': 0.0,
            b'event-metadata': 0.0,
            b'feature-activation-metadata': 0.0,
            b'info-index': 0.0,
            b'height-index': 0.0,
            b'timestamp-sorted-all': 0.0,
            b'timestamp-sorted-blocks': 0.0,
            b'timestamp-sorted-txs': 0.0,
            b'nc-state': 0.0,
            b'vertex-children': 0.0,
        })

        manager.tx_storage.pre_init()
        manager.tx_storage.indexes._manually_initialize(manager.tx_storage)

        add_new_blocks(manager, 10)

        # XXX: I had to close the DB and reinitialize the classes to force a flush of RocksDB memtables to disk
        # But I think we could do this in a better way if we had a python-binding for this Flush method in
        # https://github.com/facebook/rocksdb/blob/v7.5.3/include/rocksdb/db.h#L1396
        manager.tx_storage._db.close()

        manager = _init_manager(manager.tx_storage._rocksdb_storage.temp_dir)
        manager.metrics._collect_data()

        # We don't know exactly the sizes of each column family,
        # but we know empirically that they should be higher than these values
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'tx'] > 500)
        self.assertTrue(manager.metrics.rocksdb_cfs_sizes[b'meta'] > 1000)

    def test_peer_connections_data_collection(self):
        """Test if peer connections data is correctly being collected from the
            ConnectionsManager
        """
        # Preparation
        manager = self.create_peer('testnet')

        my_peer = manager.my_peer

        def build_hathor_protocol():
            protocol = HathorProtocol(
                my_peer=my_peer,
                p2p_manager=manager.connections,
                use_ssl=False,
                connection_type=HathorProtocol.ConnectionType.OUTGOING,
                settings=self._settings
            )
            protocol._peer = PrivatePeer.auto_generated().to_public_peer()

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
            TransactionRocksDBStorage
        """
        from hathor.nanocontracts.storage import NCRocksDBStorageFactory

        # Preparation
        rocksdb_storage = self.create_rocksdb_storage()
        nc_storage_factory = NCRocksDBStorageFactory(rocksdb_storage)
        vertex_children_service = RocksDBVertexChildrenService(rocksdb_storage)
        indexes = RocksDBIndexesManager(rocksdb_storage=rocksdb_storage, settings=self._settings)
        tx_storage = TransactionRocksDBStorage(
            reactor=self.reactor,
            rocksdb_storage=rocksdb_storage,
            settings=self._settings,
            vertex_parser=VertexParser(settings=self._settings),
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
            indexes=indexes,
            cache_config=CacheConfig(),
        )

        manager = self.create_peer('testnet', tx_storage=tx_storage)
        data = tx_storage.cache_data
        data.hit = 10
        data.miss = 20

        # Execution
        manager.metrics._collect_data()

        # Assertion
        self.assertEquals(manager.metrics.transaction_cache_hits, 10)
        self.assertEquals(manager.metrics.transaction_cache_misses, 20)
