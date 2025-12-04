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

from unittest.mock import Mock

from hathor import Blueprint, Context, public
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.pubsub import HathorEvents
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        raise Exception('always fail')


class WalletEventsTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)

    def _has_address_history_event(self, *, mock: Mock, tx: Transaction) -> bool:
        for call in mock.mock_calls:
            event_type, event_args = call.args
            assert event_type == HathorEvents.WALLET_ADDRESS_HISTORY
            history = getattr(event_args, 'history')
            if history['tx_id'] == tx.hash_hex:
                return True
        return False

    def test_update_spent_by(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_deposit = 10 HTR

            # both tx2 and nc1 spend tx0
            tx0.out[0] <<< tx2
            tx0.out[1] <<< nc1

            # tx2 and tx3 are in conflict because they spend the same output from tx1
            tx1.out[0] <<< tx2
            tx1.out[0] <<< tx3
            tx2.weight = 2
            tx3.weight = 1

            # b11 executes nc1, making it fail and become voided
            nc1 <-- b11

            # b12 confirms tx3, voiding tx2
            tx3 <-- b12
            b12.weight = 3

            tx0 < tx1 < tx2 < tx3 < nc1
        ''')

        tx0, tx2, tx3, nc1 = artifacts.get_typed_vertices(('tx0', 'tx2', 'tx3', 'nc1'), Transaction)
        b11, = artifacts.get_typed_vertices(('b11',), Block)

        event_handler = Mock()
        self.manager.pubsub.subscribe(HathorEvents.WALLET_ADDRESS_HISTORY, event_handler)

        artifacts.propagate_with(self.manager, up_to='tx0')
        self.run_to_completion()

        assert tx0.get_metadata().spent_outputs == {0: [], 1: []}
        assert tx0.get_metadata().get_output_spent_by(0) is None
        assert tx0.get_metadata().get_output_spent_by(1) is None

        assert self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()

        artifacts.propagate_with(self.manager, up_to='tx2')
        self.run_to_completion()

        assert tx0.get_metadata().spent_outputs == {0: [tx2.hash], 1: []}
        assert tx0.get_metadata().get_output_spent_by(0) == tx2.hash
        assert tx0.get_metadata().get_output_spent_by(1) is None
        assert tx2.get_metadata().voided_by is None

        assert self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()

        artifacts.propagate_with(self.manager, up_to='tx3')
        self.run_to_completion()

        assert tx0.get_metadata().spent_outputs == {0: [tx2.hash], 1: []}
        assert tx0.get_metadata().get_output_spent_by(0) == tx2.hash
        assert tx0.get_metadata().get_output_spent_by(1) is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by == {tx3.hash}

        assert not self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()

        artifacts.propagate_with(self.manager, up_to='nc1')
        self.run_to_completion()

        assert nc1.get_metadata().first_block is None
        assert nc1.get_metadata().nc_execution is None
        assert nc1.get_metadata().voided_by is None
        assert tx0.get_metadata().spent_outputs == {0: [tx2.hash], 1: [nc1.hash]}
        assert tx0.get_metadata().get_output_spent_by(0) == tx2.hash
        assert tx0.get_metadata().get_output_spent_by(1) == nc1.hash

        assert self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()

        artifacts.propagate_with(self.manager, up_to='b11')
        self.run_to_completion()

        assert nc1.get_metadata().first_block == b11.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert nc1.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, nc1.hash}
        assert tx0.get_metadata().spent_outputs == {0: [tx2.hash], 1: [nc1.hash]}
        assert tx0.get_metadata().get_output_spent_by(0) == tx2.hash
        assert tx0.get_metadata().get_output_spent_by(1) is None

        assert self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()

        artifacts.propagate_with(self.manager, up_to='b12')
        self.run_to_completion()

        assert tx0.get_metadata().spent_outputs == {0: [tx2.hash], 1: [nc1.hash]}
        assert tx0.get_metadata().get_output_spent_by(0) is None
        assert tx0.get_metadata().get_output_spent_by(1) is None
        assert tx2.get_metadata().voided_by == {tx2.hash}
        assert tx3.get_metadata().voided_by is None

        assert self._has_address_history_event(mock=event_handler, tx=tx0)
        event_handler.reset_mock()
