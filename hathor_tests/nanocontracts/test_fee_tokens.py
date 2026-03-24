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

import pytest

from hathor import Blueprint, Context, ContractId, NCActionType, public
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.headers import FeeHeader
from hathor.transaction.headers.fee_header import FeeHeaderEntry
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.scripts import Opcode
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
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
    def create_fee_token(self, ctx: Context) -> None:
        self.syscall.create_fee_token(
            token_name='fee-based token',
            token_symbol='FBT',
            amount=10 ** 9,
        )

    @public(allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass


class FeeTokensTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_postponed_verification_success(self) -> None:
        """Postponed verification means running verify_sum on NC execution-time instead of verification-time."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()
            tx2.fee = 1 HTR

            tx1 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().voided_by is None

    def test_postponed_verification_fail_nonexistent(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = nop()
            tx2.fee = 1 HTR

            tx1 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, tx2.hash}

        # It fails with a balance error caused by the withdrawal,
        # because this check runs before the postponed verify_sum.
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b12.hash,
            reason='NCInsufficientFunds: negative balance for contract',
        )

    def test_postponed_verification_fail_with_dbt(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_deposit_token()
            tx2.fee = 1 HTR

            tx1 < tx2
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
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, tx2.hash}

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b12.hash,
            reason='InputOutputMismatch: Fee amount is different than expected. (amount=1, expected=0)',
        )

    def test_postponed_verification_fail_melt_htr(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()
            tx2.fee = 1 HTR
            tx2.out[0] = 1000 HTR

            tx1 < b11 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)

        removed_htr_output = tx2.outputs.pop()
        assert removed_htr_output.token_data == 0
        assert removed_htr_output.value == 1000
        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, tx2.hash}

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b12.hash,
            reason='InputOutputMismatch: There\'s an invalid deficit of HTR. (amount=-1000, expected=0)',
        )

    def test_postponed_verification_fail_mint_htr(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()
            tx2.fee = 1 HTR

            tx1 < b11 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        extra_htr_output = TxOutput(value=1000, script=b'')
        tx2.outputs.append(fbt_output)
        tx2.outputs.append(extra_htr_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        # Verification of minting HTR is not postponed, so it fails in verification-time.
        with pytest.raises(Exception) as e:
            artifacts.propagate_with(self.manager, up_to='tx2')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            'full validation failed: There\'s an invalid surplus of HTR. (amount=1000, expected=0)'
        )

    def test_postponed_verification_pay_fee_with_fbt(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()

            tx1 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9 - 100, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        fee_entry = FeeHeaderEntry(token_index=1, amount=100)
        fee_header = FeeHeader(self._settings, tx2, [fee_entry])
        tx2.headers.append(fee_header)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, tx2.hash}

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b12.hash,
            reason=f'InvalidToken: token {fbt_id.hex()} cannot be used to pay fees',
        )

    def test_postponed_verification_tx_spending_nano(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()
            tx2.fee = 1 HTR

            tx3.fee = 1 HTR

            tx1 < b11 < tx2 < tx3 < b12
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2, tx3 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)
        tx3.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)
        tx3.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        fbt_input = TxInput(tx_id=tx2.hash, index=len(tx2.outputs) - 1, data=bytes([Opcode.OP_1]))
        tx3.inputs.append(fbt_input)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        with pytest.raises(Exception) as e:
            artifacts.propagate_with(self.manager, up_to='tx3')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == f'full validation failed: token uid {fbt_id.hex()} not found.'

        assert self.manager.vertex_handler.on_new_relayed_vertex(b12)
        assert tx2.get_metadata().first_block == b12.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().voided_by is None

        # Now, it's valid and accepted.
        assert self.manager.vertex_handler.on_new_relayed_vertex(tx3)
        assert tx3.get_metadata().validation.is_valid()
        assert tx3.get_metadata().voided_by is None

    async def test_postponed_verification_tx_spending_nano_on_new_block(self) -> None:
        """
        This test is analogous to `test_postponed_verification_tx_spending_nano` but both the nano and the tx that
        spends it are relayed via the `on_new_block` method, simulating a sync from another peer.
        """
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()
            tx2.fee = 1 HTR

            tx3.fee = 1 HTR

            tx1 < b11 < tx2 < tx3 < b12
            tx1 <-- b11
            tx2 <-- b12
        ''')

        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        tx1, tx2, tx3 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3'), Transaction)

        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)
        tx3.tokens.append(fbt_id)

        fbt_output = TxOutput(value=10 ** 9, script=b'', token_data=1)
        tx2.outputs.append(fbt_output)
        tx3.outputs.append(fbt_output)

        fbt_withdraw = NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10 ** 9)
        tx2_nano_header = tx2.get_nano_header()
        tx2_nano_header.nc_actions.append(fbt_withdraw)

        fbt_input = TxInput(tx_id=tx2.hash, index=len(tx2.outputs) - 1, data=bytes([Opcode.OP_1]))
        tx3.inputs.append(fbt_input)

        artifacts.propagate_with(self.manager, up_to='b11')
        assert tx1.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        deferred = self.manager.vertex_handler.on_new_block(block=b12, deps=[tx2, tx3])
        self.reactor.advance(1)

        msg = f'full validation failed: token uid {fbt_id.hex()} not found.'
        with pytest.raises(InvalidNewTransaction, match=msg):
            await deferred

        assert tx2.get_metadata().validation.is_valid()
        assert tx2.get_metadata().first_block is None
        assert tx2.get_metadata().nc_execution is None
        assert tx2.get_metadata().voided_by is None

        assert tx3.get_metadata().validation.is_initial()
        assert b12.get_metadata().validation.is_initial()

        assert self.manager.tx_storage.transaction_exists(tx2.hash)
        assert not self.manager.tx_storage.transaction_exists(tx3.hash)
        assert not self.manager.tx_storage.transaction_exists(b12.hash)
