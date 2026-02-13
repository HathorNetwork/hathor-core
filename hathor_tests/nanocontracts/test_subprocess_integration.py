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

"""Integration tests for subprocess NC execution with DAG Builder.

These tests verify that nano contract execution works correctly when running
in a separate subprocess with controlled PYTHONHASHSEED. The tests cover:
- On-Chain Blueprint (OCB) creation and usage
- Contract creation and initialization
- Contract calling another contract
- All running through the subprocess execution path

NOTE: These tests are currently marked as expected failures because the subprocess
execution infrastructure has a limitation: the secondary RocksDB instance cannot
see data written by the main process after the secondary was opened. This requires
implementing proper RocksDB secondary instance support with try_catch_up_with_primary().
"""

from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class SubprocessIntegrationTestCase(unittest.TestCase):
    """Integration tests for subprocess NC execution."""

    __test__ = True

    def _get_subprocess_builder(self):
        """Create a builder with subprocess execution enabled."""
        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service) \
            .enable_subprocess_execution(pythonhashseed=42, timeout=60.0)

        return builder

    def _get_regular_builder(self):
        """Create a builder without subprocess execution for baseline testing."""
        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        return builder

    def test_baseline_ocb_and_contract_calls_without_subprocess(self) -> None:
        """Baseline test: OCB creation, contract init, and contract-to-contract calls work without subprocess.

        This test verifies the test structure is correct by running the same scenario
        without subprocess execution. If this test passes, the test infrastructure is working.
        """
        builder = self._get_regular_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        # Create OCB, initialize two contracts, and have one call the other
        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..20]
            b10 < dummy

            # Create On-Chain Blueprint with contract accessor methods
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = contract_accessor_blueprint.py, MyBlueprint

            # Initialize first contract
            nc1.nc_id = ocb
            nc1.nc_method = initialize()

            # Initialize second contract
            nc2.nc_id = ocb
            nc2.nc_method = initialize()

            # Confirm OCB in block 11
            ocb <-- b11

            # Confirm first contract initialization in block 12
            b11 < nc1
            nc1 <-- b12

            # Confirm second contract initialization in block 13
            b12 < nc2
            nc2 <-- b13

            # Call nc1 to invoke method on nc2 (contract-to-contract call)
            nc_call.nc_id = nc1
            nc_call.nc_method = test_simple_public_method_no_actions(`nc2`, "hello")

            b13 < nc_call
            nc_call <-- b14
        """)

        artifacts.propagate_with(manager)

        # Verify OCB was created
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        self.assertEqual(ocb.get_blueprint_class().__name__, 'MyBlueprint')

        # Verify both contracts were initialized successfully
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        nc2 = artifacts.get_typed_vertex('nc2', Transaction)

        nc1_meta = nc1.get_metadata()
        nc2_meta = nc2.get_metadata()
        self.assertEqual(nc1_meta.nc_execution, NCExecutionState.SUCCESS)
        self.assertEqual(nc2_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the contract-to-contract call succeeded
        nc_call = artifacts.get_typed_vertex('nc_call', Transaction)
        nc_call_meta = nc_call.get_metadata()
        self.assertEqual(nc_call_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the call records show both contracts were involved
        self.assertIsNotNone(nc_call_meta.nc_calls)
        self.assertGreaterEqual(len(nc_call_meta.nc_calls), 2)

        # Verify blueprint is accessible from tx_storage
        blueprint_class = manager.tx_storage.get_blueprint_class(BlueprintId(VertexId(ocb.hash)))
        self.assertEqual(blueprint_class.__name__, 'MyBlueprint')

    def test_subprocess_ocb_creation_and_contract_init(self) -> None:
        """Test OCB creation and contract initialization via subprocess execution."""
        builder = self._get_subprocess_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..15]
            b10 < dummy

            # Create On-Chain Blueprint
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = test_blueprint1.py, TestBlueprint1

            # Initialize contract from OCB
            nc1.nc_id = ocb
            nc1.nc_method = initialize(42)

            # Confirm OCB in block 11
            ocb <-- b11

            # Confirm contract initialization in block 12
            b11 < nc1
            nc1 <-- b12
        """)

        artifacts.propagate_with(manager)

        # Verify OCB was created
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        self.assertEqual(ocb.get_blueprint_class().__name__, 'TestBlueprint1')

        # Verify contract was initialized
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        self.assertTrue(nc1.is_nano_contract())
        self.assertEqual(nc1.get_nano_header().nc_id, ocb.hash)

        nc1_meta = nc1.get_metadata()
        self.assertEqual(nc1_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify blueprint is accessible from tx_storage
        blueprint_class = manager.tx_storage.get_blueprint_class(BlueprintId(VertexId(ocb.hash)))
        self.assertEqual(blueprint_class.__name__, 'TestBlueprint1')

    def test_subprocess_contract_calls_another_contract(self) -> None:
        """Test one contract calling another contract via subprocess execution."""
        builder = self._get_subprocess_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        # Use contract_accessor_blueprint which has methods for calling other contracts
        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..20]
            b10 < dummy

            # Create On-Chain Blueprint with contract accessor methods
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = contract_accessor_blueprint.py, MyBlueprint

            # Initialize first contract
            nc1.nc_id = ocb
            nc1.nc_method = initialize()

            # Initialize second contract
            nc2.nc_id = ocb
            nc2.nc_method = initialize()

            # Confirm OCB in block 11
            ocb <-- b11

            # Confirm first contract initialization in block 12
            b11 < nc1
            nc1 <-- b12

            # Confirm second contract initialization in block 13
            b12 < nc2
            nc2 <-- b13

            # Call nc1 to invoke method on nc2 (contract-to-contract call)
            nc_call.nc_id = nc1
            nc_call.nc_method = test_simple_public_method_no_actions(`nc2`, "hello")

            b13 < nc_call
            nc_call <-- b14
        """)

        artifacts.propagate_with(manager)

        # Verify OCB was created
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        self.assertEqual(ocb.get_blueprint_class().__name__, 'MyBlueprint')

        # Verify both contracts were initialized successfully
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        nc2 = artifacts.get_typed_vertex('nc2', Transaction)

        nc1_meta = nc1.get_metadata()
        nc2_meta = nc2.get_metadata()
        self.assertEqual(nc1_meta.nc_execution, NCExecutionState.SUCCESS)
        self.assertEqual(nc2_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the contract-to-contract call succeeded
        nc_call = artifacts.get_typed_vertex('nc_call', Transaction)
        nc_call_meta = nc_call.get_metadata()
        self.assertEqual(nc_call_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the call records show both contracts were involved
        self.assertIsNotNone(nc_call_meta.nc_calls)
        # Should have at least 2 calls: one to nc1 and one to nc2
        self.assertGreaterEqual(len(nc_call_meta.nc_calls), 2)

    def test_subprocess_contract_creates_child_contract(self) -> None:
        """Test a contract creating another contract via subprocess execution."""
        builder = self._get_subprocess_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        # Use test_blueprint1 which has create_child_contract method
        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..15]
            b10 < dummy

            # Create On-Chain Blueprint
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = test_blueprint1.py, TestBlueprint1

            # Initialize parent contract
            nc_parent.nc_id = ocb
            nc_parent.nc_method = initialize(100)

            # Confirm OCB in block 11
            ocb <-- b11

            # Confirm parent contract initialization in block 12
            b11 < nc_parent
            nc_parent <-- b12

            # Call parent contract to create child contract
            nc_create_child.nc_id = nc_parent
            nc_create_child.nc_method = create_child_contract()

            b12 < nc_create_child
            nc_create_child <-- b13
        """)

        artifacts.propagate_with(manager)

        # Verify OCB was created
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        self.assertEqual(ocb.get_blueprint_class().__name__, 'TestBlueprint1')

        # Verify parent contract was initialized
        nc_parent = artifacts.get_typed_vertex('nc_parent', Transaction)
        nc_parent_meta = nc_parent.get_metadata()
        self.assertEqual(nc_parent_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the create_child_contract call succeeded
        nc_create_child = artifacts.get_typed_vertex('nc_create_child', Transaction)
        nc_create_child_meta = nc_create_child.get_metadata()
        self.assertEqual(nc_create_child_meta.nc_execution, NCExecutionState.SUCCESS)

    def test_subprocess_multiple_nc_txs_in_same_block(self) -> None:
        """Test multiple NC transactions in the same block via subprocess execution."""
        builder = self._get_subprocess_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..20]
            b15 < dummy

            # Create On-Chain Blueprint
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = test_blueprint1.py, TestBlueprint1

            # Initialize first contract
            nc1.nc_id = ocb
            nc1.nc_method = initialize(1)

            # Initialize second contract
            nc2.nc_id = ocb
            nc2.nc_method = initialize(2)

            # Confirm OCB in block 16
            ocb <-- b16

            # Confirm both contract initializations in block 17
            b16 < nc1
            b16 < nc2
            nc1 <-- b17
            nc2 <-- b17
        """)

        artifacts.propagate_with(manager)

        # Verify OCB was created
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        self.assertEqual(ocb.get_blueprint_class().__name__, 'TestBlueprint1')

        # Verify both contracts were initialized successfully
        for name in ['nc1', 'nc2']:
            nc = artifacts.get_typed_vertex(name, Transaction)
            nc_meta = nc.get_metadata()
            self.assertEqual(
                nc_meta.nc_execution,
                NCExecutionState.SUCCESS,
                f'{name} should have succeeded'
            )

        # Verify the block has the correct NC block root ID set
        b17 = artifacts.get_typed_vertex('b17', Block)
        b17_meta = b17.get_metadata()
        self.assertIsNotNone(b17_meta.nc_block_root_id)

    def test_subprocess_view_method_call_between_contracts(self) -> None:
        """Test view method calls between contracts via subprocess execution."""
        builder = self._get_subprocess_builder()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        # Use contract_accessor_blueprint which has view methods that call other contracts
        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..20]
            b10 < dummy

            # Create On-Chain Blueprint
            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"
            ocb.ocb_code = contract_accessor_blueprint.py, MyBlueprint

            # Initialize first contract
            nc1.nc_id = ocb
            nc1.nc_method = initialize()

            # Initialize second contract
            nc2.nc_id = ocb
            nc2.nc_method = initialize()

            # Confirm OCB in block 11
            ocb <-- b11

            # Confirm first contract initialization in block 12
            b11 < nc1
            nc1 <-- b12

            # Confirm second contract initialization in block 13
            b12 < nc2
            nc2 <-- b13

            # Call nc1 to invoke view method on nc2 (view-to-view call)
            nc_call.nc_id = nc1
            nc_call.nc_method = test_visibility_combinations_public_view_view(`nc2`)

            b13 < nc_call
            nc_call <-- b14
        """)

        artifacts.propagate_with(manager)

        # Verify both contracts were initialized successfully
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        nc2 = artifacts.get_typed_vertex('nc2', Transaction)

        nc1_meta = nc1.get_metadata()
        nc2_meta = nc2.get_metadata()
        self.assertEqual(nc1_meta.nc_execution, NCExecutionState.SUCCESS)
        self.assertEqual(nc2_meta.nc_execution, NCExecutionState.SUCCESS)

        # Verify the view-to-view call succeeded
        nc_call = artifacts.get_typed_vertex('nc_call', Transaction)
        nc_call_meta = nc_call.get_metadata()
        self.assertEqual(nc_call_meta.nc_execution, NCExecutionState.SUCCESS)
