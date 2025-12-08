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

from hathor.manager import HathorManager
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID, Blueprint, Context, public
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class EmitEventWithDictBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        # Intentionally emit a non-bytes payload; runtime type checks must reject this.
        self.syscall.emit_event({'should': 'fail'})  # type: ignore[arg-type]


class EmitEventPayloadTestCase(BlueprintTestCase):
    def build_manager(self) -> HathorManager:
        # Lower reward spend requirement to avoid reward-lock interference in this focused test.
        settings = self._settings._replace(REWARD_SPEND_MIN_BLOCKS=1)
        return self.create_peer(
            'unittests',
            nc_indexes=True,
            wallet_index=True,
            settings=settings,
        )

    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(EmitEventWithDictBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_emit_event_requires_bytes_payload(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..5]
            b3 < dummy     # ensure enough confirmations to unlock rewards

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx1 < b4 < b5
            tx1 <-- b4
        ''')

        b4 = artifacts.get_typed_vertex('b4', Block)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        # Executing the contract must fail because emit_event payload is not bytes.
        artifacts.propagate_with(self.manager, up_to='b4')
        meta = tx1.get_metadata()
        assert meta.first_block == b4.hash
        assert meta.nc_execution == NCExecutionState.FAILURE
        assert meta.voided_by == {NC_EXECUTION_FAIL_ID, tx1.hash}
