from unittest.mock import Mock

import pytest

from hathor.builder import CliBuilder, ResourcesBuilder
from hathor.cli.run_node_args import RunNodeArgs
from hathor.event import EventManager
from hathor.event.storage import EventMemoryStorage, EventRocksDBStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.exception import BuilderError
from hathor.indexes import MemoryIndexesManager, RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.p2p.sync_version import SyncVersion
from hathor.transaction.storage import TransactionCacheStorage, TransactionMemoryStorage, TransactionRocksDBStorage
from hathor.wallet import HDWallet, Wallet
from tests import unittest
from tests.utils import HAS_ROCKSDB


class BuilderTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.reactor = self.clock

        from hathor.cli.run_node import RunNode
        self.parser = RunNode.create_parser()

    def _build_with_error(self, cmd_args: list[str], err_msg: str) -> None:
        raw_args = self.parser.parse_args(cmd_args)
        args = RunNodeArgs.parse_obj(vars(raw_args))
        builder = CliBuilder(args)
        with self.assertRaises(BuilderError) as cm:
            manager = builder.create_manager(self.reactor)
            self.resources_builder = ResourcesBuilder(manager, args, builder.event_ws_factory, Mock())
            self.resources_builder.build()
        self.assertEqual(err_msg, str(cm.exception))

    def _build(self, cmd_args: list[str]) -> HathorManager:
        raw_args = self.parser.parse_args(cmd_args)
        args = RunNodeArgs.parse_obj(vars(raw_args))
        builder = CliBuilder(args)
        manager = builder.create_manager(self.reactor)
        self.assertIsNotNone(manager)
        self.resources_builder = ResourcesBuilder(manager, args, builder.event_ws_factory, Mock())
        self.resources_builder.build()
        return manager

    def test_empty(self):
        self._build_with_error([], '--data is expected')

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_all_default(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionCacheStorage)
        self.assertIsInstance(manager.tx_storage.store, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)
        self.assertIsNone(manager.wallet)
        self.assertEqual('unittests', manager.network)
        self.assertFalse(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))
        self.assertFalse(self.resources_builder._built_prometheus)
        self.assertFalse(self.resources_builder._built_status)
        self.assertFalse(manager._enable_event_queue)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_disable_cache_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--disable-cache', '--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_default_storage_memory_indexes(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--memory-indexes', '--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionCacheStorage)
        self.assertIsInstance(manager.tx_storage.store, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, MemoryIndexesManager)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_default_storage_with_rocksdb_indexes(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--x-rocksdb-indexes', '--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionCacheStorage)
        self.assertIsInstance(manager.tx_storage.store, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_rocksdb_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--rocksdb-storage', '--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionCacheStorage)
        self.assertIsInstance(manager.tx_storage.store, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)

    def test_memory_storage(self):
        manager = self._build(['--memory-storage'])
        self.assertIsInstance(manager.tx_storage, TransactionMemoryStorage)
        self.assertIsInstance(manager.tx_storage.indexes, MemoryIndexesManager)

    def test_memory_storage_with_rocksdb_indexes(self):
        self._build_with_error(['--memory-storage', '--x-rocksdb-indexes'], 'RocksDB indexes require RocksDB data')

    def test_sync_default(self):
        manager = self._build(['--memory-storage'])
        self.assertFalse(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_bridge(self):
        manager = self._build(['--memory-storage', '--x-sync-bridge'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_bridge2(self):
        manager = self._build(['--memory-storage', '--sync-bridge'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_v2_only(self):
        manager = self._build(['--memory-storage', '--x-sync-v2-only'])
        self.assertFalse(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_v2_only2(self):
        manager = self._build(['--memory-storage', '--sync-v2-only'])
        self.assertFalse(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_v1_only(self):
        manager = self._build(['--memory-storage', '--sync-v1-only'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V1_1))
        self.assertFalse(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_keypair_wallet(self):
        manager = self._build(['--memory-storage', '--wallet', 'keypair'])
        self.assertIsInstance(manager.wallet, Wallet)

    def test_hd_wallet(self):
        manager = self._build(['--memory-storage', '--wallet', 'hd'])
        self.assertIsInstance(manager.wallet, HDWallet)

    def test_invalid_wallet(self):
        self._build_with_error(['--memory-storage', '--wallet', 'invalid-wallet'], 'Invalid type of wallet')

    def test_status(self):
        self._build([
            '--memory-storage',
            '--status', '8080',
            '--utxo-index',
            '--enable-debug-api',
            '--enable-crash-api'
        ])
        self.assertTrue(self.resources_builder._built_status)
        self.clean_pending(required_to_quiesce=False)

    def test_prometheus_no_data(self):
        args = ['--memory-storage', '--prometheus']
        self._build_with_error(args, 'To run prometheus exporter you must have a data path')

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_prometheus(self):
        data_dir = self.mkdtemp()
        self._build(['--prometheus', '--data', data_dir])
        self.assertTrue(self.resources_builder._built_prometheus)
        self.clean_pending(required_to_quiesce=False)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_memory_and_rocksdb_indexes(self):
        data_dir = self.mkdtemp()
        args = ['--memory-indexes', '--x-rocksdb-indexes', '--data', data_dir]
        self._build_with_error(args, 'You cannot use --memory-indexes and --x-rocksdb-indexes.')

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_event_queue_with_rocksdb_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--x-enable-event-queue', '--rocksdb-storage', '--data', data_dir])

        self.assertIsInstance(manager._event_manager, EventManager)
        self.assertIsInstance(manager._event_manager._event_storage, EventRocksDBStorage)
        self.assertIsInstance(manager._event_manager._event_ws_factory, EventWebsocketFactory)
        self.assertTrue(manager._enable_event_queue)

    def test_event_queue_with_memory_storage(self):
        manager = self._build(['--x-enable-event-queue', '--memory-storage'])

        self.assertIsInstance(manager._event_manager, EventManager)
        self.assertIsInstance(manager._event_manager._event_storage, EventMemoryStorage)
        self.assertIsInstance(manager._event_manager._event_ws_factory, EventWebsocketFactory)
        self.assertTrue(manager._enable_event_queue)

    def test_event_queue_with_full_verification(self):
        args = ['--x-enable-event-queue', '--memory-storage', '--x-full-verification']
        self._build_with_error(args, '--x-full-verification cannot be used with --x-enable-event-queue')
