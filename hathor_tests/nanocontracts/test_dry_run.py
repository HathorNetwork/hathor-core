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

"""Tests for NCDryRunBlockExecutor.

These tests validate the detailed execution results from the dry-run executor,
including transaction status, call records, events, and state changes.
"""

import unittest

from hathor.nanocontracts.execution.dry_run_block_executor import (
    DryRunCallRecord,
    DryRunResult,
    DryRunTxResult,
    ExecutionStatus,
    NCDryRunBlockExecutor,
)
from hathor_cli.nc_dry_run import format_dry_run_text
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.fixtures.dry_run import (
    DryRunTestBlueprint,
    build_complex_dry_run_dag,
    build_dry_run_dag,
)


class NCDryRunExecutorTest(BlueprintTestCase):
    """Tests for NCDryRunBlockExecutor with detailed validation."""

    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(DryRunTestBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_dry_run_basic_execution(self) -> None:
        """Test basic dry-run execution returns correct structure."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(fixture.block_with_nc)

        # Validate result structure
        self.assertTrue(result.success)
        self.assertEqual(result.block_hash, fixture.block_with_nc.hash)
        self.assertEqual(result.block_height, fixture.block_with_nc.get_height())
        self.assertTrue(result.root_id_matches)
        self.assertIsNone(result.warning)

        # Validate NC sorted calls
        self.assertEqual(len(result.nc_sorted_calls), fixture.expected_tx_count)
        self.assertIn(fixture.nc_tx_increment.hash, result.nc_sorted_calls)

        # Validate transactions
        self.assertEqual(len(result.transactions), fixture.expected_tx_count)

    def test_dry_run_with_target_tx(self) -> None:
        """Test dry-run with target transaction hash."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(
            fixture.block_with_nc,
            target_tx_hash=fixture.nc_tx_increment.hash,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.target_tx_hash, fixture.nc_tx_increment.hash)

    def test_dry_run_include_changes(self) -> None:
        """Test dry-run with include_changes flag returns state changes."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(fixture.block_with_nc, include_changes=True)

        self.assertTrue(result.success)

        # Verify at least one transaction has call records with changes
        has_changes = False
        for tx_result in result.transactions:
            for call_record in tx_result.call_records:
                if call_record.changes is not None:
                    has_changes = True
                    # Verify changes have expected structure
                    for change in call_record.changes:
                        self.assertIn('key', change)
                        self.assertIn('value', change)
                    break
        self.assertTrue(has_changes, 'Expected at least one call record with changes')

    def test_dry_run_multiple_blocks(self) -> None:
        """Test dry-run can execute multiple different blocks from the same DAG."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)

        # Execute on block with NC transactions
        result1 = dry_run_executor.execute(fixture.block_with_nc)
        self.assertTrue(result1.success)
        self.assertEqual(len(result1.transactions), fixture.expected_tx_count)

        # Execute on block without NC transactions
        result2 = dry_run_executor.execute(fixture.block_without_nc)
        self.assertTrue(result2.success)
        self.assertEqual(len(result2.transactions), 0)

    def test_dry_run_block_without_nc(self) -> None:
        """Test dry-run on block without NC transactions."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(fixture.block_without_nc)

        self.assertTrue(result.success)
        self.assertEqual(result.block_hash, fixture.block_without_nc.hash)
        self.assertEqual(len(result.nc_sorted_calls), 0)
        self.assertEqual(len(result.transactions), 0)
        self.assertTrue(result.root_id_matches)

    def test_dry_run_call_records_structure(self) -> None:
        """Test that call records have correct structure and content."""
        fixture = build_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(fixture.block_with_nc)

        # Find the increment transaction result
        tx_result = next(
            (tx for tx in result.transactions if tx.tx_hash == fixture.nc_tx_increment.hash),
            None,
        )
        assert tx_result is not None
        self.assertEqual(tx_result.execution_status, 'success')
        self.assertGreater(len(tx_result.call_records), 0)

        # Validate call record structure
        call_record = tx_result.call_records[0]
        self.assertEqual(call_record.type, 'public')
        self.assertEqual(call_record.depth, 0)
        self.assertEqual(call_record.method_name, 'increment')
        self.assertIsInstance(call_record.index_updates, list)

    def test_dry_run_failure_cascade(self) -> None:
        """Test that a failed tx results in FAILURE and dependent txs are SKIPPED."""
        fixture, expected = build_complex_dry_run_dag(self.dag_builder, self.blueprint_id)
        fixture.artifacts.propagate_with(self.manager)

        block_executor = self.manager.consensus_algorithm._block_executor
        dry_run_executor = NCDryRunBlockExecutor(block_executor)
        result = dry_run_executor.execute(fixture.block_with_nc)

        self.assertTrue(result.success)

        # Count statuses
        statuses = [tx.execution_status for tx in result.transactions]
        failure_count = statuses.count(ExecutionStatus.FAILURE)
        skipped_count = statuses.count(ExecutionStatus.SKIPPED)

        self.assertEqual(failure_count, expected.failure_tx_count)
        self.assertEqual(skipped_count, expected.skipped_tx_count)

        # Verify the failed tx has exception info
        failed_txs = [tx for tx in result.transactions if tx.execution_status == ExecutionStatus.FAILURE]
        for tx in failed_txs:
            self.assertIsNotNone(tx.exception_type)
            self.assertIsNotNone(tx.exception_message)


class DryRunResultSerializationTest(unittest.TestCase):
    """Tests for DryRunResult serialization."""

    def test_result_dict_serialization(self) -> None:
        """Test DryRunResult.dict() produces valid dict."""
        call_record = DryRunCallRecord(
            type='public',
            depth=0,
            contract_id=b'\xab' * 32,
            blueprint_id=b'\xde' * 32,
            method_name='test_method',
            index_updates=[{'type': 'update_token_balance', 'amount': 100}],
            changes=[{'key': 'abc', 'value': '123'}],
        )

        tx_result = DryRunTxResult(
            tx_hash=b'\xaa' * 32,
            rng_seed=b'\xdd' * 32,
            execution_status=ExecutionStatus.SUCCESS,
            call_records=[call_record],
            events=[{'nc_id': 'nc1', 'data': 'event_data'}],
        )

        result = DryRunResult(
            block_hash=b'\x11' * 32,
            block_height=100,
            initial_block_root_id=b'\x44' * 32,
            final_block_root_id=b'\x66' * 32,
            expected_block_root_id=b'\x66' * 32,
            root_id_matches=True,
            nc_sorted_calls=[b'\xaa' * 32],
            transactions=[tx_result],
            target_tx_hash=b'\xaa' * 32,
            warning=None,
        )

        result_dict = result.model_dump()

        self.assertEqual(result_dict['success'], True)
        self.assertEqual(result_dict['block_hash'], '11' * 32)
        self.assertEqual(result_dict['block_height'], 100)
        self.assertEqual(result_dict['root_id_matches'], True)
        self.assertEqual(len(result_dict['transactions']), 1)
        self.assertEqual(result_dict['transactions'][0]['tx_hash'], 'aa' * 32)
        self.assertEqual(len(result_dict['transactions'][0]['call_records']), 1)

    def test_result_json_serialization(self) -> None:
        """Test DryRunResult.json_dumpb() produces valid JSON."""
        result = DryRunResult(
            block_hash=b'\x11' * 32,
            block_height=100,
            initial_block_root_id=b'\x44' * 32,
            final_block_root_id=b'\x66' * 32,
            expected_block_root_id=b'\x66' * 32,
            root_id_matches=True,
            nc_sorted_calls=[],
            transactions=[],
        )

        json_bytes = result.json_dumpb()
        self.assertIsInstance(json_bytes, bytes)
        self.assertIn(b'11' * 32, json_bytes)

    def test_result_model_dump_json(self) -> None:
        """Test DryRunResult.model_dump_json() produces valid JSON string (used by CLI)."""
        result = DryRunResult(
            block_hash=b'\x11' * 32,
            block_height=100,
            initial_block_root_id=b'\x44' * 32,
            final_block_root_id=b'\x66' * 32,
            expected_block_root_id=b'\x66' * 32,
            root_id_matches=True,
            nc_sorted_calls=[],
            transactions=[],
        )

        json_str = result.model_dump_json(indent=2)
        self.assertIsInstance(json_str, str)
        self.assertIn('11' * 32, json_str)


class FormatDryRunTextTest(unittest.TestCase):
    """Tests for format_dry_run_text function."""

    def test_format_success(self) -> None:
        """Test format_dry_run_text with successful execution."""
        call_record = DryRunCallRecord(
            type='public',
            depth=0,
            contract_id=b'\xab' * 32,
            blueprint_id=b'\xde' * 32,
            method_name='test_method',
            index_updates=[],
        )

        tx_result = DryRunTxResult(
            tx_hash=b'\xaa' * 32,
            rng_seed=b'\xdd' * 32,
            execution_status=ExecutionStatus.SUCCESS,
            call_records=[call_record],
            events=[],
        )

        result = DryRunResult(
            block_hash=b'\x11' * 32,
            block_height=100,
            initial_block_root_id=b'\x44' * 32,
            final_block_root_id=b'\x66' * 32,
            expected_block_root_id=b'\x66' * 32,
            root_id_matches=True,
            nc_sorted_calls=[b'\xaa' * 32],
            transactions=[tx_result],
        )

        text = format_dry_run_text(result)

        self.assertIn('height: 100', text)
        self.assertIn('Root Match:    OK', text)
        self.assertIn('Status: SUCCESS', text)
        self.assertIn('test_method', text)

    def test_format_failure(self) -> None:
        """Test format_dry_run_text with failure."""
        tx_result = DryRunTxResult(
            tx_hash=b'\xaa' * 32,
            rng_seed=b'\xdd' * 32,
            execution_status=ExecutionStatus.FAILURE,
            exception_type='NCFail',
            exception_message='Test error',
            traceback='Traceback line 1\nTraceback line 2',
        )

        result = DryRunResult(
            block_hash=b'\x11' * 32,
            block_height=100,
            initial_block_root_id=b'\x44' * 32,
            final_block_root_id=b'\x66' * 32,
            expected_block_root_id=b'\x88' * 32,
            root_id_matches=False,
            nc_sorted_calls=[b'\xaa' * 32],
            transactions=[tx_result],
            warning='Non-deterministic execution detected',
        )

        text = format_dry_run_text(result, verbose=True)

        self.assertIn('MISMATCH', text)
        self.assertIn('Status: FAILURE', text)
        self.assertIn('NCFail', text)
        self.assertIn('Test error', text)
        self.assertIn('Traceback line 1', text)
