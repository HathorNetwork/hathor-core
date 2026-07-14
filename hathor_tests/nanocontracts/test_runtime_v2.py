# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0


import pytest
from htr_lib import UnsignedAmount

from hathor import Blueprint, Context, public
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason
from hathorlib.conf.settings import HATHOR_TOKEN_UID, FeatureSetting
from hathorlib.nanocontracts import NanoRuntimeVersion
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import TokenUid


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> int:
        settings = self.syscall.get_settings()
        return settings.fee_policies[TokenUid(HATHOR_TOKEN_UID)].fee_based_tokens


class TestRuntimeV2(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()

    def test_syscall_get_settings_v1(self) -> None:
        self.runner = self.build_runner(NanoRuntimeVersion.V1)
        with pytest.raises(NCFail, match='syscall `get_settings` is not yet supported'):
            self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_syscall_get_settings_v2(self) -> None:
        self.runner = self.build_runner(NanoRuntimeVersion.V2)
        result = self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())
        # The V1 fee policy charges 0.01 HTR per output, and the runner reports it in V1 units.
        assert result == 1

    def test_activation(self) -> None:
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.REDUCE_DAA_TARGET: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    version='0.0.0'
                )
            }
        )
        settings = self._settings.copy(update=dict(
            ENABLE_DAA_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))

        feature_service = self.manager.feature_service
        feature_service._feature_settings = feature_settings
        self.manager.consensus_algorithm.block_executor._settings = settings
        self.manager.blueprint_service.register_blueprint(self.blueprint_id, MyBlueprint)

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = "{self.blueprint_id.hex()}"
            nc2.nc_method = initialize()

            nc1 <-- b12
            nc2 <-- b13
        ''')

        b5, b6, b7, b11, b12, b13 = artifacts.get_typed_vertices(('b5', 'b6', 'b7', 'b11', 'b12', 'b13'), Block)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        # Update b13 reward for the DAA update.
        assert len(b13.outputs) == 1
        b13.outputs[0].value = UnsignedAmount.from_v1(1600)
        artifacts.propagate_with(self.manager)

        assert feature_service.get_state(block=b7, feature=Feature.REDUCE_DAA_TARGET) == FeatureState.STARTED
        assert feature_service.get_state(block=b11, feature=Feature.REDUCE_DAA_TARGET) == FeatureState.LOCKED_IN
        assert feature_service.get_state(block=b12, feature=Feature.REDUCE_DAA_TARGET) == FeatureState.ACTIVE

        # Nano Runtime V2 activation uses the first_block's parent state
        assert nc1.get_metadata().first_block == b12.hash
        assert nc2.get_metadata().first_block == b13.hash

        assert nc1.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, nc1.hash}
        assert nc1.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc1.hash,
            block_id=b12.hash,
            reason='syscall `get_settings` is not yet supported',
        )

        assert nc2.get_metadata().voided_by is None
        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS
