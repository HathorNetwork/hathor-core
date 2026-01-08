from unittest.mock import Mock

from hathor.builder import ResourcesBuilder
from hathor.event import EventManager
from hathor.event.storage import EventRocksDBStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.exception import BuilderError
from hathor.indexes import RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.whitelist import URLPeersWhitelist
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.wallet import HDWallet, Wallet
from hathor_cli.builder import CliBuilder
from hathor_cli.run_node_args import RunNodeArgs
from hathor_tests import unittest


class BuilderTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.reactor = self.clock

        from hathor_cli.run_node import RunNode
        self.parser = RunNode.create_parser()

    def _build_with_error(self, cmd_args: list[str], err_msg: str) -> None:
        raw_args = self.parser.parse_args(cmd_args)
        args = RunNodeArgs.model_validate(vars(raw_args))
        builder = CliBuilder(args)
        with self.assertRaises(BuilderError) as cm:
            manager = builder.create_manager(self.reactor)
            self.resources_builder = ResourcesBuilder(manager, args, builder.event_ws_factory, Mock())
            self.resources_builder.build()
        self.assertEqual(err_msg, str(cm.exception))

    def _build(self, cmd_args: list[str]) -> HathorManager:
        raw_args = self.parser.parse_args(cmd_args)
        args = RunNodeArgs.model_validate(vars(raw_args))
        builder = CliBuilder(args)
        manager = builder.create_manager(self.reactor)
        self.assertIsNotNone(manager)
        self.resources_builder = ResourcesBuilder(manager, args, builder.event_ws_factory, Mock())
        self.resources_builder.build()
        return manager

    def test_empty(self):
        self._build_with_error([], 'either --data or --temp-data is expected')

    def test_all_default(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionRocksDBStorage)
        self.assertIsNotNone(manager.tx_storage.cache_data)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)
        self.assertIsNone(manager.wallet)
        self.assertEqual('unittests', manager.network)
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))
        self.assertFalse(self.resources_builder._built_prometheus)
        self.assertFalse(self.resources_builder._built_status)
        self.assertFalse(manager._enable_event_queue)

    def test_disable_cache_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--disable-cache', '--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionRocksDBStorage)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)

    def test_rocksdb_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--data', data_dir])
        self.assertIsInstance(manager.tx_storage, TransactionRocksDBStorage)
        self.assertIsNotNone(manager.tx_storage.cache_data)
        self.assertIsInstance(manager.tx_storage.indexes, RocksDBIndexesManager)

    def test_sync_default(self):
        manager = self._build(['--temp-data'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_bridge(self):
        self._build_with_error(['--temp-data', '--x-sync-bridge'], '--x-sync-bridge was removed')

    def test_sync_bridge2(self):
        self._build_with_error(['--temp-data', '--sync-bridge'], '--sync-bridge was removed')

    def test_sync_v2_only(self):
        manager = self._build(['--temp-data', '--x-sync-v2-only'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_v2_only2(self):
        manager = self._build(['--temp-data', '--sync-v2-only'])
        self.assertTrue(manager.connections.is_sync_version_enabled(SyncVersion.V2))

    def test_sync_v1_only(self):
        self._build_with_error(['--temp-data', '--sync-v1-only'], '--sync-v1-only was removed')

    def test_keypair_wallet(self):
        manager = self._build(['--temp-data', '--wallet', 'keypair'])
        self.assertIsInstance(manager.wallet, Wallet)

    def test_hd_wallet(self):
        manager = self._build(['--temp-data', '--wallet', 'hd'])
        self.assertIsInstance(manager.wallet, HDWallet)

    def test_invalid_wallet(self):
        self._build_with_error(['--temp-data', '--wallet', 'invalid-wallet'], 'Invalid type of wallet')

    def test_status(self):
        self._build([
            '--temp-data',
            '--status', '8080',
            '--utxo-index',
            '--enable-debug-api',
            '--enable-crash-api'
        ])
        self.assertTrue(self.resources_builder._built_status)
        self.clean_pending(required_to_quiesce=False)

    def test_prometheus_no_data(self):
        args = ['--temp-data', '--prometheus']
        self._build_with_error(args, 'To run prometheus exporter you must have a data path')

    def test_prometheus(self):
        data_dir = self.mkdtemp()
        self._build(['--prometheus', '--data', data_dir])
        self.assertTrue(self.resources_builder._built_prometheus)
        self.clean_pending(required_to_quiesce=False)

    def test_event_queue_with_rocksdb_storage(self):
        data_dir = self.mkdtemp()
        manager = self._build(['--x-enable-event-queue', '--data', data_dir])

        self.assertIsInstance(manager._event_manager, EventManager)
        self.assertIsInstance(manager._event_manager._event_storage, EventRocksDBStorage)
        self.assertIsInstance(manager._event_manager._event_ws_factory, EventWebsocketFactory)
        self.assertTrue(manager._enable_event_queue)

    def test_whitelist_cli_args(self):
        """Test --x-p2p-whitelist and --x-p2p-whitelist-only CLI arguments."""
        # Test with whitelist URL
        manager = self._build(['--temp-data', '--x-p2p-whitelist', 'https://example.com/whitelist'])
        self.assertIsNotNone(manager.connections.peers_whitelist)
        self.assertIsInstance(manager.connections.peers_whitelist, URLPeersWhitelist)

        # Test with whitelist-only flag (now a no-op, whitelist always enforces)
        manager2 = self._build([
            '--temp-data', '--x-p2p-whitelist', 'https://example.com/whitelist',
            '--x-p2p-whitelist-only',
        ])
        self.assertIsNotNone(manager2.connections.peers_whitelist)

        # Test with disabled whitelist
        manager3 = self._build(['--temp-data', '--x-p2p-whitelist', 'none'])
        self.assertIsNone(manager3.connections.peers_whitelist)
