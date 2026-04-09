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

from hathor import Blueprint, Context, ContractId, NCActionType, public
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction, TxOutput
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public(allow_deposit=True, allow_withdrawal=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def create_deposit_token(self, ctx: Context) -> None:
        self.syscall.create_deposit_token(
            token_name='deposit-based token',
            token_symbol='DBT',
            amount=100,
        )

    @public(allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass


class TokenCreationTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_create_dbt_and_withdraw_on_another_tx(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_deposit_token()

            tx3.nc_id = tx1
            tx3.nc_method = nop()

            tx1 < b11 < tx2 < b12 < tx3 < b13
            tx1 <-- b11
            tx2 <-- b12
            tx3 <-- b13
        ''')

        b11, b12, b13 = artifacts.get_typed_vertices(('b11', 'b12', 'b13'), Block)
        tx1, tx2, tx3 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3'), Transaction)

        dbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='DBT')
        tx3.tokens.append(dbt_id)

        dbt_output = TxOutput(value=100, script=b'', token_data=1)
        tx3.outputs.append(dbt_output)

        dbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=100)
        tx3_nano_header = tx3.get_nano_header()
        tx3_nano_header.nc_actions.append(dbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert tx3.get_metadata().first_block == b13.hash
        assert tx3.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx3.get_metadata().voided_by is None

    def test_create_dbt_and_withdraw_on_another_tx_before_block(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_deposit_token()

            tx3.nc_id = tx1
            tx3.nc_method = nop()

            tx1 < b11 < tx2 < tx3 < b12 < b13
            tx1 <-- b11
            tx2 <-- b12
            tx3 <-- b13
        ''')

        b11, b12, b13 = artifacts.get_typed_vertices(('b11', 'b12', 'b13'), Block)
        tx1, tx2, tx3 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3'), Transaction)

        dbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='DBT')
        tx3.tokens.append(dbt_id)

        dbt_output = TxOutput(value=100, script=b'', token_data=1)
        tx3.outputs.append(dbt_output)

        dbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=100)
        tx3_nano_header = tx3.get_nano_header()
        tx3_nano_header.nc_actions.append(dbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert tx3.get_metadata().first_block == b13.hash
        assert tx3.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx3.get_metadata().voided_by is None

    def test_create_dbt_and_withdraw_on_same_tx(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_deposit_token()

            tx1 < b11 < tx2 < b12
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        dbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='DBT')
        tx2.tokens.append(dbt_id)

        dbt_output = TxOutput(value=100, script=b'', token_data=1)
        tx2.outputs.append(dbt_output)

        dbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=100)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(dbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().voided_by is None

    def test_withdraw_nonexistent_token(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx1 <-- b11
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        tx1, = artifacts.get_typed_vertices(('tx1',), Transaction)

        fake_token_id = self.gen_random_token_uid()
        tx1.tokens.append(fake_token_id)

        fake_output = TxOutput(value=100, script=b'', token_data=1)
        tx1.outputs.append(fake_output)

        fake_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=100)
        tx1_nano_header = tx1.get_nano_header()
        tx1_nano_header.nc_actions.append(fake_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx1.get_metadata().voided_by is not None
