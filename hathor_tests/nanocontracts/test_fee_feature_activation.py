#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest

from hathor import Blueprint, BlueprintId, Context, ContractId, NCActionType, public
from hathor.conf.settings import FeatureSetting
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction, TxOutput
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason


class FeeTokenBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def create_fee_token(self, ctx: Context) -> None:
        self.syscall.create_fee_token(
            token_name='fee-based token',
            token_symbol='FBT',
            amount=10 ** 9,
        )


class TestFeeFeatureActivation(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.FEE_TOKENS: Criteria(
                    bit=3,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0'
                )
            }
        )

        settings = self._settings._replace(
            ENABLE_FEE=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        )
        daa = DifficultyAdjustmentAlgorithm(settings=self._settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa(daa).set_nc_log_config(NCLogConfig.FAILED)

        self.manager = self.create_peer_from_builder(builder)
        self.vertex_handler = self.manager.vertex_handler
        self.feature_service = self.manager.feature_service
        self.bit_signaling_service = self.manager._bit_signaling_service
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_fee_activation(self) -> None:
        """Test that fee feature activation works correctly through the feature activation process."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy < b11

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx1.out[0] = 123 FBT
            tx1.fee = 1 HTR

            b12 < FBT < tx1 < b13
        ''')

        b3, b4, b7, b8, b11, b12, b13 = artifacts.get_typed_vertices(
            ('b3', 'b4', 'b7', 'b8', 'b11', 'b12', 'b13'),
            Block,
        )
        fbt, tx1 = artifacts.get_typed_vertices(('FBT', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager, up_to='b3')
        assert self.feature_service.get_state(block=b3, feature=Feature.FEE_TOKENS) == FeatureState.DEFINED

        artifacts.propagate_with(self.manager, up_to='b4')
        assert self.feature_service.get_state(block=b4, feature=Feature.FEE_TOKENS) == FeatureState.STARTED

        signaling_blocks = ('b5', 'b6', 'b7')
        for block_name in signaling_blocks:
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

        assert self.feature_service.get_state(block=b7, feature=Feature.FEE_TOKENS) == FeatureState.STARTED

        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        # At this point, the fee feature is not active, so the fee txs are rejected on the mempool.
        msg = 'full validation failed: Header `FeeHeader` not supported by'
        with pytest.raises(InvalidNewTransaction, match=msg):
            self.vertex_handler.on_new_relayed_vertex(fbt)
        assert fbt.get_metadata().validation.is_initial()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.FEE_TOKENS) == FeatureState.ACTIVE

        # Now, the fee txs are accepted on the mempool.
        artifacts.propagate_with(self.manager, up_to='FBT')
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='tx1')
        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert b13.get_metadata().validation.is_valid()
        assert b13.get_metadata().voided_by is None

    def test_fee_syscall_before_activation(self) -> None:
        """Test that create_fee_token syscall fails when fee feature is not yet active."""
        # Register the blueprint
        blueprint_id = BlueprintId(self.rng.randbytes(32))
        self.manager.tx_storage.nc_catalog.blueprints[blueprint_id] = FeeTokenBlueprint

        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy < b11

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_deposit = 1 HTR

            nc2.nc_id = nc1
            nc2.nc_method = create_fee_token()

            b11 < nc1 < nc2 < b12

            nc1 <-- b12
            nc2 <-- b12
        ''')

        b8, b11, b12 = artifacts.get_typed_vertices(('b8', 'b11', 'b12'), Block)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(nc1.hash), token_symbol='FBT')
        nc2.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        nc2.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        nc2_nano_header = nc2.get_nano_header()
        nc2_nano_header.nc_actions.append(fbt_withdraw)

        # Propagate b1-b4 first
        artifacts.propagate_with(self.manager, up_to='b4')

        # Propagate with signaling (b5, b6, b7) to activate feature
        signaling_blocks = ('b5', 'b6', 'b7')
        for block_name in signaling_blocks:
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = self.manager.tx_storage
            block.signal_bits = self.bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(self.manager, up_to=block_name)

        artifacts.propagate_with(self.manager, up_to='b8')
        assert self.feature_service.get_state(block=b8, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        artifacts.propagate_with(self.manager, up_to='b11')
        assert self.feature_service.get_state(block=b11, feature=Feature.FEE_TOKENS) == FeatureState.LOCKED_IN

        # Propagate b12 which includes nc1 and nc2
        # nc2 should fail because the fee feature is not yet active at the time of execution
        artifacts.propagate_with(self.manager, up_to='b12')
        assert self.feature_service.get_state(block=b12, feature=Feature.FEE_TOKENS) == FeatureState.ACTIVE

        # nc1 (initialize) should succeed
        assert nc1.get_metadata().first_block == b12.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc1.get_metadata().voided_by is None

        # nc2 (create_fee_token) should fail because the syscall checks if fee is active
        assert nc2.get_metadata().first_block == b12.hash
        assert nc2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert nc2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, nc2.hash}

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc2.hash,
            block_id=b12.hash,
            reason='NCInvalidSyscall: fee feature is not active',
        )
