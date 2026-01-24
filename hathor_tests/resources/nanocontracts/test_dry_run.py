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

"""Tests for NCDryRunResource HTTP API.

These tests focus on validating the HTTP API behavior and JSON serialization,
not the detailed execution results (which are tested in the executor tests).
"""

from twisted.internet.defer import inlineCallbacks

from hathor.nanocontracts.resources.dry_run import NCDryRunResource
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.fixtures.dry_run import build_dry_run_dag, register_dry_run_blueprint
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class NCDryRunResourceTest(_BaseResourceTest._ResourceTest):
    """Tests for NCDryRunResource HTTP API."""

    def setUp(self, *, utxo_index: bool = False, unlock_wallet: bool = True) -> None:
        super().setUp(utxo_index=utxo_index, unlock_wallet=unlock_wallet)
        self.manager = self.create_peer('unittests', nc_indexes=True)
        self.tx_storage = self.manager.tx_storage

        self.blueprint_id = register_dry_run_blueprint(self.manager)
        self.web = StubSite(NCDryRunResource(self.manager))
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    # =========================================================================
    # Error handling tests
    # =========================================================================

    @inlineCallbacks
    def test_missing_params(self):
        """Test error when neither block_hash nor tx_hash provided."""
        response = yield self.web.get('dry_run')
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Must specify either block_hash or tx_hash', data['error'])

    @inlineCallbacks
    def test_both_params_error(self):
        """Test error when both block_hash and tx_hash provided."""
        response = yield self.web.get('dry_run', {
            b'block_hash': b'abc123',
            b'tx_hash': b'def456',
        })
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Cannot specify both', data['error'])

    @inlineCallbacks
    def test_invalid_block_hash(self):
        """Test error with invalid block_hash."""
        response = yield self.web.get('dry_run', {
            b'block_hash': b'not_hex',
        })
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Invalid block_hash', data['error'])

    @inlineCallbacks
    def test_invalid_tx_hash(self):
        """Test error with invalid tx_hash."""
        response = yield self.web.get('dry_run', {
            b'tx_hash': b'not_hex',
        })
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Invalid tx_hash', data['error'])

    @inlineCallbacks
    def test_block_not_found(self):
        """Test error when block not found."""
        response = yield self.web.get('dry_run', {
            b'block_hash': b'00' * 32,
        })
        self.assertEqual(404, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Block not found', data['error'])

    @inlineCallbacks
    def test_tx_not_found(self):
        """Test error when transaction not found."""
        response = yield self.web.get('dry_run', {
            b'tx_hash': b'00' * 32,
        })
        self.assertEqual(404, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('Transaction not found', data['error'])

    @inlineCallbacks
    def test_genesis_block_error(self):
        """Test error when trying to dry-run genesis block."""
        genesis_blocks = [tx for tx in self.tx_storage.get_all_genesis() if tx.is_block]
        genesis_block = genesis_blocks[0]

        response = yield self.web.get('dry_run', {
            b'block_hash': genesis_block.hash.hex().encode('ascii'),
        })
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('genesis block', data['error'])

    @inlineCallbacks
    def test_tx_not_nano_contract_error(self):
        """Test error when tx_hash points to a non-NC transaction."""
        genesis_txs = [tx for tx in self.tx_storage.get_all_genesis() if not tx.is_block]
        genesis_tx = genesis_txs[0]

        response = yield self.web.get('dry_run', {
            b'tx_hash': genesis_tx.hash.hex().encode('ascii'),
        })
        self.assertEqual(400, response.responseCode)
        data = response.json_value()
        self.assertFalse(data['success'])
        self.assertIn('not a nano contract', data['error'])

    # =========================================================================
    # Serialization tests - validate JSON output structure
    # =========================================================================

    @inlineCallbacks
    def test_dry_run_block_serialization(self):
        """Test successful dry-run with block_hash serializes correctly."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        response = yield self.web.get('dry_run', {
            b'block_hash': fixture.block_with_nc.hash.hex().encode('ascii'),
        })
        self.assertEqual(200, response.responseCode)

        # Validate JSON structure (not detailed values)
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIn('block_hash', data)
        self.assertIn('block_height', data)
        self.assertIn('initial_block_root_id', data)
        self.assertIn('final_block_root_id', data)
        self.assertIn('expected_block_root_id', data)
        self.assertIn('root_id_matches', data)
        self.assertIn('nc_sorted_calls', data)
        self.assertIn('transactions', data)
        self.assertIsInstance(data['transactions'], list)

    @inlineCallbacks
    def test_dry_run_tx_serialization(self):
        """Test successful dry-run with tx_hash serializes correctly."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        response = yield self.web.get('dry_run', {
            b'tx_hash': fixture.nc_tx_increment.hash.hex().encode('ascii'),
        })
        self.assertEqual(200, response.responseCode)

        # Validate JSON structure includes target_tx_hash
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertIn('target_tx_hash', data)
        self.assertEqual(data['target_tx_hash'], fixture.nc_tx_increment.hash.hex())

    @inlineCallbacks
    def test_dry_run_include_changes_serialization(self):
        """Test dry-run with include_changes serializes changes correctly."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        response = yield self.web.get('dry_run', {
            b'block_hash': fixture.block_with_nc.hash.hex().encode('ascii'),
            b'include_changes': b'true',
        })
        self.assertEqual(200, response.responseCode)

        # Validate JSON structure includes changes
        data = response.json_value()
        self.assertTrue(data['success'])

        # Check that changes field is present in call records
        for tx_result in data['transactions']:
            self.assertIn('call_records', tx_result)
            for call_record in tx_result['call_records']:
                # changes should be present (may be empty list or have items)
                self.assertIn('changes', call_record)

    @inlineCallbacks
    def test_dry_run_transaction_result_structure(self):
        """Test transaction result has all expected fields."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        response = yield self.web.get('dry_run', {
            b'block_hash': fixture.block_with_nc.hash.hex().encode('ascii'),
        })
        self.assertEqual(200, response.responseCode)

        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertGreater(len(data['transactions']), 0)

        # Validate transaction result structure
        for tx_result in data['transactions']:
            self.assertIn('tx_hash', tx_result)
            self.assertIn('rng_seed', tx_result)
            self.assertIn('execution_status', tx_result)
            self.assertIn(tx_result['execution_status'], ['success', 'failure', 'skipped'])
            self.assertIn('call_records', tx_result)
            self.assertIn('events', tx_result)

    @inlineCallbacks
    def test_dry_run_block_without_nc_serialization(self):
        """Test dry-run on block without NC transactions serializes correctly."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        response = yield self.web.get('dry_run', {
            b'block_hash': fixture.block_without_nc.hash.hex().encode('ascii'),
        })
        self.assertEqual(200, response.responseCode)

        # Validate empty transactions list serializes correctly
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['nc_sorted_calls'], [])
        self.assertEqual(data['transactions'], [])
