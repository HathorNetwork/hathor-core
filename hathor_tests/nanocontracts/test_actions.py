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

import dataclasses
from typing import Any
from unittest.mock import patch

import pytest

from hathor.indexes.tokens_index import TokensIndex
from hathor.nanocontracts import HATHOR_TOKEN_UID, NC_EXECUTION_FAIL_ID, Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import NCInvalidAction
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import NCActionType, TokenUid
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import InvalidToken
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.util import not_none
from hathor.verification.nano_header_verifier import MAX_ACTIONS_LEN
from hathor.verification.verification_params import VerificationParams
from hathor.wallet import HDWallet
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason, set_nano_header


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_actions=[
        NCActionType.DEPOSIT,
        NCActionType.WITHDRAWAL,
        NCActionType.GRANT_AUTHORITY,
        NCActionType.ACQUIRE_AUTHORITY,
    ])
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def revoke(self, ctx: Context, token_uid: TokenUid, revoke_mint: bool, revoke_melt: bool) -> None:
        self.syscall.revoke_authorities(token_uid=token_uid, revoke_mint=revoke_mint, revoke_melt=revoke_melt)

    @public(allow_deposit=True, allow_withdrawal=True, allow_grant_authority=True)
    def mint(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        self.syscall.mint_tokens(token_uid, amount)

    @public(allow_deposit=True, allow_withdrawal=True)
    def melt(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        self.syscall.melt_tokens(token_uid, amount)


class TestActions(unittest.TestCase):
    """
    Tests in this file use a hybrid dag builder and manual approach. First, the dag builder is used to setup the
    initial state and every vertex that we'll need. Then, we manually manipulate a tx's nano header adding the
    required actions and changing inputs/outputs accordingly.

    The dag builder does not currently support authority actions. Even when it supports them, it's good to keep those
    tests manual to make basic assertions without the implicitness of the dag builder.
    """

    def setUp(self) -> None:
        super().setUp()

        self.bp_id = b'1' * 32
        self.manager = self.create_peer('unittests', nc_log_config=NCLogConfig.FAILED, wallet_index=True)

        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.bp_id: MyBlueprint
        })
        assert self.manager.tx_storage.indexes is not None
        self.tokens_index: TokensIndex = not_none(self.manager.tx_storage.indexes.tokens)
        self.nc_seqnum = 0

        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]

            tx0.nc_id = "{self.bp_id.hex()}"
            tx0.nc_method = initialize()
            tx0.nc_deposit = 1000 HTR
            tx0.nc_deposit = 1000 TKA

            # The fact that HTR is in index 0 and TKA is in index 1 is used by tests below.
            tx1.out[0] = 10000 HTR
            tx1.out[1] = 1000 TKA

            tx2.out[0] = 10000 HTR
            tx2.out[1] = 1000 TKA

            b10 < dummy < TKA < tx0
            tx0 <-- tx1 <-- b11
            b11 < tx2
            tx1 <-- tx2 <-- b12
        ''')

        # We only propagate up to tx0. The rest is manipulated and propagated by each test.
        self.artifacts.propagate_with(self.manager, up_to='tx0')

        self.b11, self.b12 = self.artifacts.get_typed_vertices(['b11', 'b12'], Block)
        self.tx0, self.tx1, self.tx2, self.tka = self.artifacts.get_typed_vertices(
            ['tx0', 'tx1', 'tx2', 'TKA'],
            Transaction,
        )
        best_block = self.manager.tx_storage.get_best_block()
        self.verification_params = VerificationParams.default_for_mempool(
            enable_nano=True,
            best_block=best_block,
        )

        # We finish a manual setup of tx1, so it can be used directly in verification methods.
        self.tx1.storage = self.manager.tx_storage
        self.tx1.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)

        # Just some constants.
        self.htr_balance_key = BalanceKey(nc_id=self.tx0.hash, token_uid=HATHOR_TOKEN_UID)
        self.tka_balance_key = BalanceKey(nc_id=self.tx0.hash, token_uid=self.tka.hash)

        # Initial state sanity check. 30 HTR are used to mint 3000 TKA.
        self.initial_htr_total = self._settings.GENESIS_TOKENS + 10 * self._settings.INITIAL_TOKENS_PER_BLOCK - 30
        self.initial_tka_total = 3000
        self._assert_token_index(htr_total=self.initial_htr_total, tka_total=self.initial_tka_total)

    def _set_nano_header(
        self,
        *,
        tx: Transaction,
        nc_actions: list[NanoHeaderAction] | None = None,
        nc_method: str | None = None,
        nc_args: tuple[Any, ...] | None = None,
    ) -> None:
        """Configure a nano header for a tx."""
        wallet = self.dag_builder.get_main_wallet()
        assert isinstance(wallet, HDWallet)
        set_nano_header(
            tx=tx,
            wallet=wallet,
            nc_id=self.tx0.hash,
            nc_actions=nc_actions,
            nc_method=nc_method,
            nc_args=nc_args,
            blueprint=MyBlueprint,
            seqnum=self.nc_seqnum
        )
        self.nc_seqnum += 1

    def _change_tx_balance(
        self,
        *,
        tx: Transaction,
        update_htr_output: int | None = None,
        update_tka_output: int | None = None,
        add_inputs: list[TxInput] | None = None,
        add_outputs: list[TxOutput] | None = None,
    ) -> None:
        """
        Modify a tx by optionally changing its HTR and TKA output values, or adding new inputs and outputs,
        then re-sign all input scripts.
        """
        if update_htr_output is not None:
            out = tx.outputs[0]
            assert tx.get_token_uid(out.get_token_index()) == HATHOR_TOKEN_UID, (
                'expected HTR in output index 0'
            )
            out.value += update_htr_output

        if update_tka_output is not None:
            out = tx.outputs[1]
            assert tx.get_token_uid(out.get_token_index()) == self.tka.hash, (
                'expected TKA in output index 1'
            )
            out.value += update_tka_output

        if add_inputs:
            tx.inputs.extend(add_inputs)

        if add_outputs:
            tx.outputs.extend(add_outputs)

        self.dag_builder._exporter.sign_all_inputs(tx)

    def _get_all_balances(self) -> dict[BalanceKey, Balance]:
        return self.manager.get_best_block_nc_storage(self.tx0.hash).get_all_balances()

    def _create_tka_mint_input(self) -> TxInput:
        """Return a new TxInput pointing to a TKA mint authority."""
        mint_index = len(self.tka.outputs) - 2
        mint_output: TxOutput = self.tka.outputs[mint_index]
        token_uid = self.tka.get_token_uid(mint_output.get_token_index())
        assert token_uid == self.tka.hash and mint_output.can_mint_token(), (
            f'expected the dag builder to generate a mint authority in output index {mint_index}'
        )
        return TxInput(tx_id=self.tka.hash, index=mint_index, data=b'')

    def _create_tka_melt_input(self) -> TxInput:
        """Return a new TxInput pointing to a TKA melt authority."""
        melt_index = len(self.tka.outputs) - 1
        melt_output: TxOutput = self.tka.outputs[melt_index]
        token_uid = self.tka.get_token_uid(melt_output.get_token_index())
        assert token_uid == self.tka.hash and melt_output.can_melt_token(), (
            f'expected the dag builder to generate a melt authority in output index {melt_index}'
        )
        return TxInput(tx_id=self.tka.hash, index=melt_index, data=b'')

    def _assert_token_index(self, *, htr_total: int, tka_total: int) -> None:
        assert self.tokens_index.get_token_info(HATHOR_TOKEN_UID).get_total() == htr_total
        assert self.tokens_index.get_token_info(self.tka.hash).get_total() == tka_total

    def test_deposit_success(self) -> None:
        # Add a DEPOSIT action and remove tokens from the HTR output accordingly.
        self._change_tx_balance(tx=self.tx1, update_htr_output=-123)
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=123),
        ])

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the added tokens.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1123, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + self._settings.INITIAL_TOKENS_PER_BLOCK,
            tka_total=self.initial_tka_total,
        )

    def test_withdrawal_success(self) -> None:
        # Add a WITHDRAWAL action and add tokens to the HTR output accordingly.
        self._change_tx_balance(tx=self.tx1, update_htr_output=123)
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=123),
        ])

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the removed tokens.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=877, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + self._settings.INITIAL_TOKENS_PER_BLOCK,
            tka_total=self.initial_tka_total,
        )

    def test_grant_authority_mint_success(self) -> None:
        # Add a GRANT_AUTHORITY action to mint TKA, and add a mint authority input accordingly.
        self._change_tx_balance(tx=self.tx1, add_inputs=[self._create_tka_mint_input()])
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK
            ),
        ])

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the mint authority.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=False),
        }

    def test_grant_authority_melt_success(self) -> None:
        # Add a GRANT_AUTHORITY action to melt TKA, and add a melt authority input accordingly.
        self._change_tx_balance(tx=self.tx1, add_inputs=[self._create_tka_melt_input()])
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MELT_MASK
            ),
        ])

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the melt authority.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=True),
        }

    def test_grant_authority_all_success(self) -> None:
        # Add a GRANT_AUTHORITY action to both mint and melt TKA, and add authority inputs accordingly.
        self._change_tx_balance(
            tx=self.tx1,
            add_inputs=[
                self._create_tka_mint_input(),
                self._create_tka_melt_input(),
            ]
        )
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.ALL_AUTHORITIES
            ),
        ])

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with both mint and melt authorities.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=True),
        }

    def _test_acquire_authority_to_create_output(self, authority: int) -> None:
        token_index = 1

        # Add an ACQUIRE_AUTHORITY action for TKA, and add a new authority output accordingly,
        # both with the provided `authority`.
        self._change_tx_balance(
            tx=self.tx2,
            add_outputs=[
                TxOutput(value=authority, script=b'', token_data=TxOutput.TOKEN_AUTHORITY_MASK | token_index)
            ]
        )
        self._set_nano_header(tx=self.tx2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=authority
            ),
        ])

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash

    def test_acquire_authority_create_mint_success(self) -> None:
        # Grant a mint authority to the nano contract and use it to create a new mint authority output.
        self.test_grant_authority_mint_success()
        self._test_acquire_authority_to_create_output(TxOutput.TOKEN_MINT_MASK)

        # Check that tx2 successfully executes.
        assert self.tx2.get_metadata().voided_by is None

    def test_acquire_authority_create_mint_nc_fail(self) -> None:
        # Try to create a new mint authority output, but the contract doesn't have that authority.
        self._test_acquire_authority_to_create_output(TxOutput.TOKEN_MINT_MASK)

        # Check that tx2 fails execution.
        assert self.tx2.get_metadata().voided_by == {self.tx2.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=self.tx2.hash,
            block_id=self.b12.hash,
            reason=f'NCInvalidAction: cannot acquire mint authority for token {self.tka.hash_hex}'
        )

    def test_acquire_authority_create_melt_success(self) -> None:
        # Grant a melt authority to the nano contract and use it to create a new melt authority output.
        self.test_grant_authority_melt_success()
        self._test_acquire_authority_to_create_output(TxOutput.TOKEN_MELT_MASK)

        # Check that tx2 successfully executes.
        assert self.tx2.get_metadata().voided_by is None

    def test_acquire_authority_create_melt_nc_fail(self) -> None:
        # Try to create a new melt authority output, but the contract doesn't have that authority.
        self._test_acquire_authority_to_create_output(TxOutput.TOKEN_MELT_MASK)

        # Check that tx2 fails execution.
        assert self.tx2.get_metadata().voided_by == {self.tx2.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=self.tx2.hash,
            block_id=self.b12.hash,
            reason=f'NCInvalidAction: cannot acquire melt authority for token {self.tka.hash_hex}'
        )

    def test_acquire_authority_create_all_success(self) -> None:
        # Grant all authorities to the nano contract and use it to create a new all authorities output.
        self.test_grant_authority_all_success()
        self._test_acquire_authority_to_create_output(TxOutput.ALL_AUTHORITIES)

        # Check that tx2 successfully executes.
        assert self.tx2.get_metadata().voided_by is None

    def test_acquire_authority_create_all_nc_fail(self) -> None:
        # Try to create a new all authorities output, but the contract doesn't have any authorities.
        self._test_acquire_authority_to_create_output(TxOutput.ALL_AUTHORITIES)

        # Check that tx2 fails execution.
        assert self.tx2.get_metadata().voided_by == {self.tx2.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=self.tx2.hash,
            block_id=self.b12.hash,
            reason=f'NCInvalidAction: cannot acquire mint authority for token {self.tka.hash_hex}'
        )

    def test_acquire_authority_mint_tokens_success(self) -> None:
        # Grant a mint authority to the nano contract and use it to mint tokens.
        self.test_grant_authority_mint_success()

        # Add an ACQUIRE_AUTHORITY action for TKA, minting new TKA, and updating the HTR balance accordingly.
        self._change_tx_balance(
            tx=self.tx2,
            update_htr_output=-10,
            update_tka_output=1000,
        )
        self._set_nano_header(tx=self.tx2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK
            ),
        ])

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash

        # Check that tx2 successfully executes.
        assert self.tx2.get_metadata().voided_by is None

    def test_acquire_authority_melt_tokens_success(self) -> None:
        # Grant a melt authority to the nano contract and use it to melt tokens.
        self.test_grant_authority_melt_success()

        # Add an ACQUIRE_AUTHORITY action for TKA, melting TKA, and updating the HTR balance accordingly.
        self._change_tx_balance(
            tx=self.tx2,
            update_htr_output=5,
            update_tka_output=-500,
        )
        self._set_nano_header(tx=self.tx2, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MELT_MASK
            ),
        ])

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash

        # Check that tx2 successfully executes.
        assert self.tx2.get_metadata().voided_by is None

    def _test_mint_tokens_success(self, *, invert_actions_order: bool) -> None:
        # Grant a TKA mint authority to the nano contract and then use it to mint tokens.
        self.test_grant_authority_mint_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=False),
        }

        # Add actions so both minted tokens and htr used to mint tokens are in/from the tx outputs/inputs.
        self._change_tx_balance(tx=self.tx2, update_htr_output=-200, update_tka_output=20000)
        nc_actions = [
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=20000),
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=200),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=nc_actions,
            nc_method='mint',
            nc_args=(self.tka.hash, 20000),
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is unchanged because both
        # minted tokens and HTR used to mint in/were from tx outputs/inputs.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=False),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK - 200,
            tka_total=self.initial_tka_total + 20000,
        )

    def test_mint_tokens_success(self) -> None:
        self._test_mint_tokens_success(invert_actions_order=False)

    def test_mint_tokens_success_inverted(self) -> None:
        self._test_mint_tokens_success(invert_actions_order=True)

    def test_grant_and_mint_same_tx_success(self) -> None:
        # Add a GRANT_AUTHORITY action to mint TKA, and add a mint authority input accordingly.
        # Also add a call to mint
        self._change_tx_balance(tx=self.tx1, add_inputs=[self._create_tka_mint_input()])
        self._set_nano_header(
            tx=self.tx1,
            nc_actions=[
                NanoHeaderAction(type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK),
            ],
            nc_method='mint',
            nc_args=(self.tka.hash, 200)
        )

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the mint authority.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=998, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1200, can_mint=True, can_melt=False),
        }

    def test_mint_tokens_keep_in_contract_success(self) -> None:
        # Grant a TKA mint authority to the nano contract and then use it to mint tokens.
        self.test_grant_authority_mint_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=False),
        }

        # Add a deposit action, paying for HTR with the input and keeping the minted token in the contract.
        self._change_tx_balance(tx=self.tx2, update_htr_output=-200)
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=[NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=200)],
            nc_method='mint',
            nc_args=(self.tka.hash, 20000)
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is updated.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=21000, can_mint=True, can_melt=False),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK - 200,
            tka_total=self.initial_tka_total + 20000,
        )

    def _test_mint_tokens_and_partial_withdrawal_success(self, *, invert_actions_order: bool) -> None:
        # Grant a TKA mint authority to the nano contract and then use it to mint tokens.
        self.test_grant_authority_mint_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=True, can_melt=False),
        }

        # Add actions paying for HTR with the input and withdrawing part of the minted token from the contract.
        self._change_tx_balance(tx=self.tx2, update_htr_output=-200, update_tka_output=10000)
        nc_actions = [
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=1, amount=10000),
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=200),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=nc_actions,
            nc_method='mint',
            nc_args=(self.tka.hash, 20000)
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is updated.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=11000, can_mint=True, can_melt=False),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK - 200,
            tka_total=self.initial_tka_total + 20000,
        )

    def test_mint_tokens_and_partial_withdrawal_success(self) -> None:
        self._test_mint_tokens_and_partial_withdrawal_success(invert_actions_order=False)

    def test_mint_tokens_and_partial_withdrawal_success_inverted(self) -> None:
        self._test_mint_tokens_and_partial_withdrawal_success(invert_actions_order=True)

    def _test_melt_tokens_success(self, *, invert_actions_order: bool) -> None:
        # Grant a TKA melt authority to the nano contract and then use it to melt tokens.
        self.test_grant_authority_melt_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=True),
        }

        # Add actions so both melted tokens and htr received from melt are from/in the tx inputs/outputs.
        self._change_tx_balance(tx=self.tx2, update_htr_output=5, update_tka_output=-500)
        nc_actions = [
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=1, amount=500),
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=5),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=nc_actions,
            nc_method='melt',
            nc_args=(self.tka.hash, 500)
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is unchanged because both
        # melted tokens and HTR received are from/in the tx inputs/outputs.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=True),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK + 5,
            tka_total=self.initial_tka_total - 500,
        )

    def test_melt_tokens_success(self) -> None:
        self._test_melt_tokens_success(invert_actions_order=False)

    def test_melt_tokens_success_inverted(self) -> None:
        self._test_melt_tokens_success(invert_actions_order=True)

    def test_melt_tokens_from_contract_success(self) -> None:
        # Grant a TKA melt authority to the nano contract and then use it to melt tokens.
        self.test_grant_authority_melt_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=True),
        }

        # Add a withdrawal action receiving the HTR from the melt in the output and melting the tokens in the contract.
        self._change_tx_balance(tx=self.tx2, update_htr_output=5)
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=[NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=5)],
            nc_method='melt',
            nc_args=(self.tka.hash, 500)
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is updated.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=500, can_mint=False, can_melt=True),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK + 5,
            tka_total=self.initial_tka_total - 500,
        )

    def _test_melt_tokens_from_contract_and_input_success(self, *, invert_actions_order: bool) -> None:
        # Grant a TKA melt authority to the nano contract and then use it to melt tokens.
        self.test_grant_authority_melt_success()
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1000, can_mint=False, can_melt=True),
        }

        # Add actions so part of the tokens are melted from inputs and part from the contract.
        self._change_tx_balance(tx=self.tx2, update_htr_output=5, update_tka_output=-250)
        nc_actions = [
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=1, amount=250),
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=5),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx2,
            nc_actions=nc_actions,
            nc_method='melt',
            nc_args=(self.tka.hash, 500)
        )

        # Execute tx2
        self.artifacts.propagate_with(self.manager, up_to='b12')
        assert self.b12.get_metadata().voided_by is None
        assert self.tx2.get_metadata().first_block == self.b12.hash
        assert self.tx2.get_metadata().voided_by is None

        # Check that the nano contract balance is updated.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=750, can_mint=False, can_melt=True),
        }

        # Check the token index.
        self._assert_token_index(
            htr_total=self.initial_htr_total + 2 * self._settings.INITIAL_TOKENS_PER_BLOCK + 5,
            tka_total=self.initial_tka_total - 500,
        )

    def test_melt_tokens_from_contract_and_input_success(self) -> None:
        self._test_melt_tokens_from_contract_and_input_success(invert_actions_order=False)

    def test_melt_tokens_from_contract_and_input_success_inverted(self) -> None:
        self._test_melt_tokens_from_contract_and_input_success(invert_actions_order=True)

    def _test_acquire_and_grant_same_token_not_allowed(self, *, invert_actions_order: bool) -> None:
        nc_actions = [
            NanoHeaderAction(type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK),
            NanoHeaderAction(type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx1,
            nc_actions=nc_actions,
        )

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verifiers.nano_header.verify_actions(self.tx1)
        assert str(e.value) == f'conflicting actions for token {self.tka.hash_hex}'

    def test_acquire_and_grant_same_token_not_allowed(self) -> None:
        self._test_acquire_and_grant_same_token_not_allowed(invert_actions_order=False)

    def test_acquire_and_grant_same_token_not_allowed_inverted(self) -> None:
        self._test_acquire_and_grant_same_token_not_allowed(invert_actions_order=True)

    def _test_conflicting_actions(self, *, invert_actions_order: bool) -> None:
        # Add 2 conflicting actions for the same token.
        nc_actions = [
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=1),
            NanoHeaderAction(type=NCActionType.WITHDRAWAL, token_index=0, amount=2),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(tx=self.tx1, nc_actions=nc_actions)

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verifiers.nano_header.verify_actions(self.tx1)
        assert str(e.value) == 'conflicting actions for token 00'

    def test_conflicting_actions(self) -> None:
        self._test_conflicting_actions(invert_actions_order=False)

    def test_conflicting_actions_inverted(self) -> None:
        self._test_conflicting_actions(invert_actions_order=True)

    def _test_non_conflicting_actions_success(self, *, invert_actions_order: bool) -> None:
        # Add a GRANT_AUTHORITY action to mint TKA, and add a mint authority input accordingly.
        # Also add a DEPOSIT action with the same token and update the tx output accordingly.
        self._change_tx_balance(tx=self.tx1, add_inputs=[self._create_tka_mint_input()])
        self._change_tx_balance(tx=self.tx1, update_tka_output=-100)
        nc_actions = [
            NanoHeaderAction(type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK),
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=1, amount=100),
        ]
        if invert_actions_order:
            nc_actions.reverse()
        self._set_nano_header(
            tx=self.tx1,
            nc_actions=nc_actions,
        )

        # Execute tx1
        self.artifacts.propagate_with(self.manager, up_to='b11')
        assert self.b11.get_metadata().voided_by is None
        assert self.tx1.get_metadata().voided_by is None
        assert self.tx1.get_metadata().first_block == self.b11.hash

        # Check that the nano contract balance is updated with the mint authority.
        assert self._get_all_balances() == {
            self.htr_balance_key: Balance(value=1000, can_mint=False, can_melt=False),
            self.tka_balance_key: Balance(value=1100, can_mint=True, can_melt=False),
        }

    def test_non_conflicting_actions_success(self) -> None:
        self._test_non_conflicting_actions_success(invert_actions_order=False)

    def test_non_conflicting_actions_success_inverted(self) -> None:
        self._test_non_conflicting_actions_success(invert_actions_order=True)

    def test_token_index_not_found(self) -> None:
        # Add an action with a token index out of bounds.
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=2, amount=1),
        ])

        params = dataclasses.replace(self.verification_params, harden_token_restrictions=False)
        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verify(self.tx1, params)
        assert str(e.value) == 'DEPOSIT token index 2 not found'

    def test_token_uid_not_in_list(self) -> None:
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=1),
        ])

        nano_header = self.tx1.get_nano_header()
        actions = nano_header.get_actions()

        # Here I have to fake and patch get_actions() with an invalid
        # one because the nano header always creates valid token uids.
        fake_token_uid = b'\1' * 32
        fake_actions = [dataclasses.replace(actions[0], token_uid=TokenUid(fake_token_uid))]

        with patch('hathor.transaction.headers.NanoHeader.get_actions', lambda _: fake_actions):
            with pytest.raises(NCInvalidAction) as e:
                self.manager.verification_service.verifiers.nano_header.verify_actions(self.tx1)
        assert str(e.value) == f'DEPOSIT action requires token {fake_token_uid.hex()} in tokens list'

    def _test_invalid_unknown_authority(self, action_type: NCActionType) -> None:
        # Create an authority action with an unknown authority.
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=action_type, token_index=1, amount=TxOutput.ALL_AUTHORITIES + 1),
        ])

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verify(self.tx1, self.verification_params)
        assert str(e.value) == f'action {action_type.name} token {self.tka.hash_hex} invalid authorities: 0b100'

    def _test_invalid_htr_authority(self, action_type: NCActionType) -> None:
        # Create an authority action for HTR.
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(type=action_type, token_index=0, amount=TxOutput.TOKEN_MINT_MASK),
        ])

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verify(self.tx1, self.verification_params)
        assert str(e.value) == f'{action_type.name} action cannot be executed on HTR token'

    def test_invalid_grant_unknown_authority(self) -> None:
        self._test_invalid_unknown_authority(NCActionType.GRANT_AUTHORITY)

    def test_invalid_acquire_unknown_authority(self) -> None:
        self._test_invalid_unknown_authority(NCActionType.ACQUIRE_AUTHORITY)

    def test_invalid_grant_htr_authority(self) -> None:
        self._test_invalid_htr_authority(NCActionType.GRANT_AUTHORITY)

    def test_invalid_acquire_htr_authority(self) -> None:
        self._test_invalid_htr_authority(NCActionType.ACQUIRE_AUTHORITY)

    def test_grant_authority_cannot_mint(self) -> None:
        # Try to grant a TKA mint authority without an authority input.
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.GRANT_AUTHORITY,
                token_index=1,
                amount=TxOutput.TOKEN_MINT_MASK
            ),
        ])

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verify(self.tx1, self.verification_params)
        assert str(e.value) == f'GRANT_AUTHORITY token {self.tka.hash_hex} requires mint, but no input has it'

    def test_grant_authority_cannot_melt(self) -> None:
        # Try to grant a TKA melt authority without an authority input.
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.GRANT_AUTHORITY,
                token_index=1,
                amount=TxOutput.TOKEN_MELT_MASK
            ),
        ])

        with pytest.raises(NCInvalidAction) as e:
            self.manager.verification_service.verify(self.tx1, self.verification_params)
        assert str(e.value) == f'GRANT_AUTHORITY token {self.tka.hash_hex} requires melt, but no input has it'

    def test_acquire_authority_cannot_mint_with_melt(self) -> None:
        # Try to create a mint authority output with an action to acquire a melt authority.
        self._change_tx_balance(
            tx=self.tx1,
            add_outputs=[
                TxOutput(value=TxOutput.TOKEN_MINT_MASK, script=b'', token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1)
            ]
        )
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MELT_MASK
            ),
        ])

        with pytest.raises(InvalidToken, match='output at index 2 has mint authority, but no input has it'):
            self.manager.verification_service.verify(self.tx1, self.verification_params)

    def test_use_authority_cannot_melt_with_mint(self) -> None:
        # Try to create a melt authority output with an action to acquire a mint authority.
        self._change_tx_balance(
            tx=self.tx1,
            add_outputs=[
                TxOutput(value=TxOutput.TOKEN_MELT_MASK, script=b'', token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1)
            ]
        )
        self._set_nano_header(tx=self.tx1, nc_actions=[
            NanoHeaderAction(
                type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=TxOutput.TOKEN_MINT_MASK
            ),
        ])

        with pytest.raises(InvalidToken, match='output at index 2 has melt authority, but no input has it'):
            self.manager.verification_service.verify(self.tx1, self.verification_params)

    def test_actions_max_len_fail(self) -> None:
        # Try to create too many actions.
        action = NanoHeaderAction(type=NCActionType.ACQUIRE_AUTHORITY, token_index=1, amount=1)
        actions = [action] * (MAX_ACTIONS_LEN + 1)

        self._set_nano_header(tx=self.tx1, nc_actions=actions)

        with pytest.raises(NCInvalidAction, match='more actions than the max allowed: 17 > 16'):
            self.manager.verification_service.verify(self.tx1, self.verification_params)
