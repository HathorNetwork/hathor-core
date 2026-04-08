#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest

from hathor import Blueprint, Context, public
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason
from hathorlib.conf.settings import FeatureSetting
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.versions import NanoRuntimeVersion


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> int:
        settings = self.syscall.get_settings()
        return settings.fee_per_output


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
        assert result == self._settings.FEE_PER_OUTPUT

    def test_activation(self) -> None:
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.NANO_RUNTIME_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    version='0.0.0'
                )
            }
        )
        settings = self._settings.copy(update=dict(
            ENABLE_NANO_RUNTIME_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))

        self.manager = self.create_peer('unittests', nc_log_config=NCLogConfig.FAILED, settings=settings)
        self.manager.blueprint_service.register_blueprint(self.blueprint_id, MyBlueprint)
        feature_service = self.manager.feature_service

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
        artifacts.propagate_with(self.manager)

        b5, b6, b7, b11, b12, b13 = artifacts.get_typed_vertices(('b5', 'b6', 'b7', 'b11', 'b12', 'b13'), Block)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        assert feature_service.get_state(block=b7, feature=Feature.NANO_RUNTIME_V2) == FeatureState.STARTED
        assert feature_service.get_state(block=b11, feature=Feature.NANO_RUNTIME_V2) == FeatureState.LOCKED_IN
        assert feature_service.get_state(block=b12, feature=Feature.NANO_RUNTIME_V2) == FeatureState.ACTIVE

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
