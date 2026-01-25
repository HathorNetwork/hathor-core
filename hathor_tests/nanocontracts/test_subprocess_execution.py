# Copyright 2025 Hathor Labs
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

"""Tests for subprocess execution infrastructure."""

import tempfile

from hathor.builder.builder import Builder
from hathor.conf.get_settings import HathorSettings
from hathor.nanocontracts.execution.subprocess_pool import NCSubprocessPool
from hathor.nanocontracts.execution.subprocess_worker import (
    DataRequest,
    DataResponse,
    ExecuteBlockCommand,
    SubprocessTxStorageProxy,
    WorkerInitConfig,
)
from hathor.storage import RocksDBStorage
from hathor_tests import unittest


class SubprocessInfrastructureTestCase(unittest.TestCase):
    """Test subprocess execution infrastructure."""
    __test__ = True

    def test_builder_enable_subprocess_execution(self):
        """Test that builder can enable subprocess execution."""
        builder = Builder()
        builder.set_settings(HathorSettings())

        # Enable subprocess execution
        builder.enable_subprocess_execution(pythonhashseed=42, timeout=60.0)

        self.assertTrue(builder._enable_subprocess_execution)
        self.assertEqual(builder._subprocess_pythonhashseed, 42)
        self.assertEqual(builder._subprocess_timeout, 60.0)

    def test_rocksdb_read_only_mode(self):
        """Test that RocksDB can be opened in read-only mode."""
        # Create a database
        temp_dir = tempfile.mkdtemp()
        primary_storage = RocksDBStorage(path=temp_dir)

        # Open it in read-only mode
        secondary_path = tempfile.mkdtemp()
        read_only_storage = RocksDBStorage(
            path=temp_dir,
            secondary_path=secondary_path,
        )

        self.assertTrue(read_only_storage._is_secondary)
        self.assertFalse(primary_storage._is_secondary)

        # Both should be able to read
        primary_db = primary_storage.get_db()
        read_only_db = read_only_storage.get_db()

        self.assertIsNotNone(primary_db)
        self.assertIsNotNone(read_only_db)

    def test_worker_init_config_has_nc_catalog(self):
        """Test that WorkerInitConfig includes nc_catalog_pickle."""
        import pickle

        settings = HathorSettings()
        nc_catalog = {}  # Simplified for testing

        config = WorkerInitConfig(
            settings_pickle=pickle.dumps(settings),
            nc_catalog_pickle=pickle.dumps(nc_catalog),
        )

        self.assertEqual(pickle.loads(config.nc_catalog_pickle), {})

    def test_execute_block_command_has_required_fields(self):
        """Test that ExecuteBlockCommand has all required fields."""
        command = ExecuteBlockCommand(
            block_bytes=b'block_data',
            nc_tx_bytes_list=[b'tx1', b'tx2'],
            should_skip_tx_hashes=frozenset([b'skip1']),
            parent_root_id=b'root_id',
            block_height=42,
        )

        self.assertEqual(command.block_bytes, b'block_data')
        self.assertEqual(command.nc_tx_bytes_list, [b'tx1', b'tx2'])
        self.assertEqual(command.should_skip_tx_hashes, frozenset([b'skip1']))
        self.assertEqual(command.parent_root_id, b'root_id')
        self.assertEqual(command.block_height, 42)

    def test_data_request_response_types(self):
        """Test DataRequest and DataResponse message types."""
        request = DataRequest(
            request_id=1,
            request_type='token_creation_tx',
            request_data=b'token_uid',
        )
        self.assertEqual(request.request_id, 1)
        self.assertEqual(request.request_type, 'token_creation_tx')
        self.assertEqual(request.request_data, b'token_uid')

        response = DataResponse(
            request_id=1,
            response_data=b'tx_data',
        )
        self.assertEqual(response.request_id, 1)
        self.assertEqual(response.response_data, b'tx_data')

    def test_subprocess_tx_storage_proxy_blueprint_lookup(self):
        """Test SubprocessTxStorageProxy blueprint lookup from local catalog."""
        from unittest.mock import MagicMock

        # Create a mock nc_catalog
        mock_catalog = MagicMock()
        mock_blueprint_class = type('TestBlueprint', (), {})
        mock_catalog.get_blueprint_class.return_value = mock_blueprint_class

        # Create mock settings
        mock_settings = MagicMock()

        # Create proxy
        proxy = SubprocessTxStorageProxy(
            nc_catalog=mock_catalog,
            settings=mock_settings,
            request_func=lambda t, d: None,
        )

        # Test blueprint lookup from local catalog
        blueprint_id = b'test_blueprint_id'
        result = proxy.get_blueprint_class(blueprint_id)

        mock_catalog.get_blueprint_class.assert_called_once_with(blueprint_id)
        self.assertEqual(result, mock_blueprint_class)

    def test_subprocess_tx_storage_proxy_token_lookup_requests_main(self):
        """Test SubprocessTxStorageProxy token lookup requests from main process."""
        from unittest.mock import MagicMock

        # Create a mock nc_catalog that doesn't have the blueprint
        mock_catalog = MagicMock()
        mock_catalog.get_blueprint_class.return_value = None

        # Create mock settings
        mock_settings = HathorSettings()

        # Create a mock request function that returns token creation tx bytes
        mock_request_func = MagicMock()

        # Create proxy
        proxy = SubprocessTxStorageProxy(
            nc_catalog=mock_catalog,
            settings=mock_settings,
            request_func=mock_request_func,
        )

        # Test token lookup
        token_uid = b'test_token_uid'
        mock_request_func.return_value = None  # Simulate not found

        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        with self.assertRaises(TransactionDoesNotExist):
            proxy.get_token_creation_transaction(token_uid)

        mock_request_func.assert_called_once_with('token_creation_tx', token_uid)

    def test_communication_metrics_record_message(self):
        """Test CommunicationMetrics message recording."""
        from hathor.nanocontracts.execution.subprocess_pool import CommunicationMetrics

        metrics = CommunicationMetrics()

        # Record some messages
        metrics.record_message('EffectResponse', 1000.0)
        metrics.record_message('EffectResponse', 1001.0)
        metrics.record_message('DataRequest:trie_get', 1002.0,
                               request_data_size=32, response_data_size=256, processing_time=0.001)
        metrics.record_message('DataRequest:trie_get', 1003.0,
                               request_data_size=32, response_data_size=128, processing_time=0.002)
        metrics.record_message('BlockCompleteResponse', 1004.0)

        # Check message counts
        self.assertEqual(metrics.message_counts['EffectResponse'], 2)
        self.assertEqual(metrics.message_counts['DataRequest:trie_get'], 2)
        self.assertEqual(metrics.message_counts['BlockCompleteResponse'], 1)

        # Check aggregated stats
        self.assertEqual(metrics.total_request_data_bytes['DataRequest:trie_get'], 64)
        self.assertEqual(metrics.total_response_data_bytes['DataRequest:trie_get'], 384)
        self.assertAlmostEqual(metrics.total_processing_time['DataRequest:trie_get'], 0.003, places=6)

        # Check summary
        summary = metrics.get_summary()
        self.assertEqual(summary['total_messages'], 5)
        self.assertAlmostEqual(summary['avg_processing_time']['DataRequest:trie_get'], 0.0015, places=6)

    def test_communication_metrics_reset(self):
        """Test CommunicationMetrics reset functionality."""
        from hathor.nanocontracts.execution.subprocess_pool import CommunicationMetrics

        metrics = CommunicationMetrics()

        # Record some messages
        metrics.record_message('EffectResponse', 1000.0)
        metrics.record_message('DataRequest:trie_get', 1001.0,
                               request_data_size=32, response_data_size=256, processing_time=0.001)

        # Verify data exists
        self.assertEqual(metrics.message_counts['EffectResponse'], 1)
        self.assertEqual(len(metrics.message_records), 2)

        # Reset
        metrics.reset()

        # Verify all cleared
        self.assertEqual(len(metrics.message_counts), 0)
        self.assertEqual(len(metrics.message_records), 0)
        self.assertEqual(len(metrics.total_request_data_bytes), 0)
        self.assertEqual(len(metrics.total_response_data_bytes), 0)
        self.assertEqual(len(metrics.total_processing_time), 0)

    def test_message_record_dataclass(self):
        """Test MessageRecord dataclass."""
        from hathor.nanocontracts.execution.subprocess_pool import MessageRecord

        record = MessageRecord(
            message_type='DataRequest:trie_get',
            timestamp=1000.5,
            request_data_size=32,
            response_data_size=256,
            processing_time=0.001,
        )

        self.assertEqual(record.message_type, 'DataRequest:trie_get')
        self.assertEqual(record.timestamp, 1000.5)
        self.assertEqual(record.request_data_size, 32)
        self.assertEqual(record.response_data_size, 256)
        self.assertEqual(record.processing_time, 0.001)
