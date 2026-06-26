# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""HTR deposit/withdraw economics for minting and melting deposit tokens under V2.

A deposit token locks HTR proportional to the amount minted (`TOKEN_DEPOSIT_PERCENTAGE`, 1%) and returns HTR
when melted. Under V2 the percentage is applied to the amount's `normalized()` value and the result is rounded
to a whole V1 cent: the deposit rounds UP (so the protocol is never short-changed) and the withdraw rounds
DOWN (so melting never returns more than was locked). That ceil/floor asymmetry means a mint-then-melt round
trip of a non-cent-aligned amount permanently retains one cent. The math is done in exact integer arithmetic,
so it stays correct at the magnitudes V2's 18-decimal amounts reach, where 64-bit float would lose precision.

These tests drive the economics three ways: the accepting cases through the DAG builder, the deposit/withdraw
formulas as pure-function contracts, and the rejecting cases by mutating a built tx and re-running the balance
verifier directly (mutation invalidates the input scripts, which the full pipeline checks before the balance).
"""

from __future__ import annotations

import math
import re

import pytest
from htr_lib import UnsignedAmount

from hathor.transaction import Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfoDict
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.token_info import TokenVersion

# One V2 "cent": the smallest unit a V1 amount can express, written at V2's 18-decimal scale. Deposits ceil up
# to a multiple of this and withdraws floor down to one.
ONE_V2_CENT = 10 ** 16
# One whole token at V2 scale; minting one more whole token raises the required 1% deposit by exactly one cent.
ONE_V2_TOKEN = 10 ** 18


class TestTokenCreationEconomicsV2(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.settings = self.manager._settings
        self.tx_verifier = self.manager.verification_service.verifiers.tx
        self._numerator = self.settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR
        self._denominator = self.settings.TOKEN_DEPOSIT_PERCENTAGE_DENOMINATOR

    # -- helpers --------------------------------------------------------------------------------------------

    def _token_dict(self, tx: Transaction) -> TokenInfoDict:
        params = self.get_verification_params(self.manager)
        block_storage = self.manager.verification_service._get_block_storage(params)
        return tx.get_complete_token_info(block_storage)

    def _verify_balance(self, tx: Transaction) -> None:
        """Run only the input/output balance check, reading the tx's (possibly mutated) outputs directly."""
        self.tx_verifier.verify_transparent_balance(self.settings, tx, self._token_dict(tx))

    def _htr_consumed(self, tx: Transaction) -> UnsignedAmount:
        """The net HTR a tx locks: `inputs - outputs` of the native token, i.e. the deposit it pays."""
        htr_info = self._token_dict(tx)[self.settings.HATHOR_TOKEN_UID]
        return (-htr_info.amount).to_unsigned()

    def _minted_amount(self, tx: Transaction) -> UnsignedAmount:
        """The amount of the single deposit token this creation tx mints (its positive `TokenInfo`)."""
        deposit_infos = [ti for ti in self._token_dict(tx).values() if ti.version == TokenVersion.DEPOSIT]
        assert len(deposit_infos) == 1
        return deposit_infos[0].amount.to_unsigned()

    def _output_index(self, tx: Transaction, *, token_data: int, authority: bool) -> int:
        for index, output in enumerate(tx.outputs):
            if output.token_data == token_data and output.is_token_authority() == authority:
                return index
        raise AssertionError(f'no output with token_data={token_data} authority={authority}')

    def _ref_deposit(self, mint_normalized: int) -> int:
        """Reference deposit in normalized units: ceil(1% of mint) then ceil up to a whole cent."""
        rounded_up_to_1 = -(-mint_normalized * self._numerator // self._denominator)
        return -(-rounded_up_to_1 // ONE_V2_CENT) * ONE_V2_CENT

    def _ref_withdraw(self, melt_normalized: int) -> int:
        """Reference withdraw in normalized units: floor(1% of melt) then floor down to a whole cent."""
        rounded_down_to_0 = melt_normalized * self._numerator // self._denominator
        return rounded_down_to_0 // ONE_V2_CENT * ONE_V2_CENT

    def _build_v2_token(self, mint_amount: str) -> TokenCreationTransaction:
        """Build and propagate a V2 deposit-token creation minting `mint_amount` of token `TK` (e.g. '2.0').

        The token-creation vertex `TK` carries the deposit economics; `mint_tx` is the separate vertex that
        receives the minted tokens.
        """
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            mint_tx.out[0] = {mint_amount} TK
            mint_tx.token_amount_version = V2
            TK.token_amount_version = V2

            b11 < mint_tx
            mint_tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        return artifacts.get_typed_vertex('TK', TokenCreationTransaction)

    def _build_v2_melt_tx(self, tk: TokenCreationTransaction, *, melt_normalized: int,
                          withdraw: UnsignedAmount) -> Transaction:
        """Build (unsigned) a V2 melt tx that burns `melt_normalized` of `tk`'s token and withdraws `withdraw`.

        Only the transparent balance is exercised, so the inputs are left unsigned; the melt authority input
        is spent so the token may be melted.
        """
        token_index = self._output_index(tk, token_data=1, authority=False)
        melt_index = next(i for i, o in enumerate(tk.outputs)
                          if o.is_token_authority() and o.value.raw() == TxOutput.TOKEN_MELT_MASK)
        script = tk.outputs[token_index].script
        remaining = UnsignedAmount.from_v2(tk.outputs[token_index].value.raw() - melt_normalized)
        melt_passthrough = UnsignedAmount.from_v2(TxOutput.TOKEN_MELT_MASK)
        tx = Transaction(
            weight=1,
            inputs=[TxInput(tk.hash, token_index, b''), TxInput(tk.hash, melt_index, b'')],
            outputs=[
                TxOutput(remaining, script, 0b00000001),
                TxOutput(melt_passthrough, script, 0b10000001),
                TxOutput(withdraw, script, 0),
            ],
            parents=self.manager.get_new_tx_parents(),
            tokens=[tk.tokens[0]],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds()),
        )
        tx.init_static_metadata_from_storage(self.settings, self.manager.tx_storage)
        return tx

    # -- deposit (mint) happy paths -------------------------------------------------------------------------

    def test_v1_deposit_token_creation_baseline(self) -> None:
        """Control for the deposit path: a V1 deposit-token creation locks exactly
        `get_deposit_token_deposit_amount(mint)` HTR and verifies."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            mint_tx.out[0] = 100 TK

            b11 < mint_tx
            mint_tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tk = artifacts.get_typed_vertex('TK', TokenCreationTransaction)

        assert tk.get_token_amount_version() == TokenAmountVersion.V1
        expected_deposit = get_deposit_token_deposit_amount(self.settings, self._minted_amount(tk))
        assert self._htr_consumed(tk) == expected_deposit
        assert tk.get_metadata().validation.is_valid()
        assert tk.get_metadata().voided_by is None

    def test_v2_deposit_token_creation_locks_normalized_deposit(self) -> None:
        """A V2 deposit-token creation locks HTR computed from the NORMALIZED mint amount (1% of normalized,
        ceil to cent) and verifies. Minting 2.0 tokens locks 0.02 HTR."""
        tk = self._build_v2_token('2.0 TK')

        assert tk.get_token_amount_version() == TokenAmountVersion.V2
        minted = self._minted_amount(tk)
        assert minted.normalized() == 2 * ONE_V2_TOKEN
        deposit = self._htr_consumed(tk)
        assert deposit == get_deposit_token_deposit_amount(self.settings, minted)
        assert deposit.normalized() == self._ref_deposit(minted.normalized()) == 2 * ONE_V2_CENT
        assert tk.get_metadata().validation.is_valid()
        assert tk.get_metadata().voided_by is None

    def test_deposit_token_mint_with_v1_htr_input_and_v2_token_output(self) -> None:
        """A V2 token-creation tx funds its HTR deposit from a V1-created HTR utxo (a genesis output, always V1)
        while minting the new token as V2; the normalized deposit balances against the V1 input and it passes the
        balance check.

        The DAG builder's filler funds a V2 creation from a freshly minted V2 utxo, leaving no V1 input to spend,
        so this tx is constructed by hand.
        """
        genesis = self.manager.tx_storage.get_all_genesis()
        genesis_block = next(vertex for vertex in genesis if vertex.is_block)
        funding_output = genesis_block.outputs[0]
        assert funding_output.value.is_v1()

        mint = UnsignedAmount.from_v2(2 * ONE_V2_TOKEN)
        deposit = get_deposit_token_deposit_amount(self.settings, mint)
        change = UnsignedAmount.from_v2(funding_output.value.normalized() - deposit.normalized())
        script = funding_output.script
        tk = TokenCreationTransaction(
            weight=1,
            parents=[vertex.hash for vertex in genesis if not vertex.is_block],
            storage=self.manager.tx_storage,
            inputs=[TxInput(genesis_block.hash, 0, b'')],
            outputs=[
                TxOutput(mint, script, 0b00000001),
                TxOutput(UnsignedAmount.from_v2(TxOutput.TOKEN_MINT_MASK), script, 0b10000001),
                TxOutput(UnsignedAmount.from_v2(TxOutput.TOKEN_MELT_MASK), script, 0b10000001),
                TxOutput(change, script, 0),
            ],
            token_name='CrossVersionCoin',
            token_symbol='CVC',
            timestamp=int(self.clock.seconds()),
        )
        tk.signal_bits = 0b1  # mark the creation tx as V2
        # the token uid is the creation tx's hash, so it must be set before reading token info; a deterministic
        # hash (without valid proof-of-work) is enough, since only the transparent balance is exercised.
        tk.update_hash()
        tk.init_static_metadata_from_storage(self.settings, self.manager.tx_storage)

        assert tk.get_token_amount_version() == TokenAmountVersion.V2
        assert funding_output.value.is_v1()
        assert tk.outputs[0].value.is_v2()
        # the V2 deposit balances against the V1 genesis input; no exception means it verifies.
        self._verify_balance(tk)

    # -- deposit/withdraw rounding (pure-function contracts) ------------------------------------------------

    def test_v2_mint_requires_ceil_to_cent_deposit(self) -> None:
        """A V2 mint whose 1% lands between cents forces the deposit UP to the next whole cent; under-depositing
        by less than a cent is rejected. 1% of 1.005 is 0.01005, which ceils to a 0.02 deposit."""
        mint = UnsignedAmount.from_v2(1005 * 10 ** 15)  # 1.005 tokens
        deposit = get_deposit_token_deposit_amount(self.settings, mint)
        assert deposit.normalized() == 2 * ONE_V2_CENT
        # the un-rounded 1% is strictly less than the charged deposit: the remainder is rounded up, not dropped.
        assert mint.normalized() * self._numerator // self._denominator < deposit.normalized()

        tk = self._build_v2_token('1.005 TK')
        htr_index = self._output_index(tk, token_data=0, authority=False)
        # keep half a cent more HTR than the deposit allows -> under-deposit -> surplus
        tk.outputs[htr_index].value = UnsignedAmount.from_v2(tk.outputs[htr_index].value.raw() + ONE_V2_CENT // 2)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(tk)

    def test_v2_melt_withdraws_floor_to_cent(self) -> None:
        """A V2 melt returns HTR FLOORED to the whole cent; over-withdrawing by a sub-cent is rejected. 1% of
        1.005 is 0.01005, which floors to a 0.01 withdraw."""
        melt = UnsignedAmount.from_v2(1005 * 10 ** 15)  # 1.005 tokens
        withdraw = get_deposit_token_withdraw_amount(self.settings, melt)
        assert withdraw.normalized() == ONE_V2_CENT
        # the un-rounded 1% is strictly more than the returned withdraw: the remainder is dropped, not paid out.
        assert melt.normalized() * self._numerator // self._denominator > withdraw.normalized()

        tk = self._build_v2_token('2.0 TK')
        # the exact floored withdraw balances...
        ok_melt = self._build_v2_melt_tx(tk, melt_normalized=1005 * 10 ** 15, withdraw=withdraw)
        self._verify_balance(ok_melt)
        # ...but claiming half a cent more HTR than the floor allows is a surplus.
        over = UnsignedAmount.from_v2(withdraw.raw() + ONE_V2_CENT // 2)
        bad_melt = self._build_v2_melt_tx(tk, melt_normalized=1005 * 10 ** 15, withdraw=over)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(bad_melt)

    def test_minimum_deposit_is_nonzero_for_any_positive_mint(self) -> None:
        """Minting the smallest positive amount still requires a nonzero (one-cent) HTR deposit, because the 1%
        is ceiled. A token-creation tx that mints with zero deposit is rejected."""
        smallest = UnsignedAmount.from_v2(1)
        deposit = get_deposit_token_deposit_amount(self.settings, smallest)
        assert deposit.normalized() == ONE_V2_CENT
        assert deposit > UnsignedAmount.zero()

        tk = self._build_v2_token('2.0 TK')
        htr_index = self._output_index(tk, token_data=0, authority=False)
        # return the entire one-cent deposit as change -> zero net deposit -> surplus
        tk.outputs[htr_index].value = UnsignedAmount.from_v2(tk.outputs[htr_index].value.raw() + 2 * ONE_V2_CENT)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(tk)

    def test_deposit_math_backward_compatible_for_v1(self) -> None:
        """Across a range of V1 amounts the integer deposit/withdraw math equals the legacy 1% float result.
        At V1 scale (cents) the float computation is exact, so the integer refactor is byte-for-byte compatible."""
        for v1_cents in (1, 7, 100, 333, 12_345, 99_999):
            mint = UnsignedAmount.from_v1(v1_cents)
            deposit = get_deposit_token_deposit_amount(self.settings, mint)
            withdraw = get_deposit_token_withdraw_amount(self.settings, mint)

            # the legacy formula worked in whole HTR-cents: 1% of the amount, ceil for deposit, floor for withdraw.
            legacy_deposit_cents = math.ceil(v1_cents * 0.01)
            legacy_withdraw_cents = math.floor(v1_cents * 0.01)
            assert deposit.normalized() == legacy_deposit_cents * ONE_V2_CENT
            assert withdraw.normalized() == legacy_withdraw_cents * ONE_V2_CENT

    def test_deposit_math_no_float_precision_loss_at_v2_scale(self) -> None:
        """At a magnitude only V2 amounts reach, the integer deposit (ceil) and withdraw (floor) are exact to the
        unit, where a 64-bit float intermediate would round and disagree."""
        mint_normalized = 10 ** 30 + 5 * 10 ** 15  # huge, with a sub-cent tail
        mint = UnsignedAmount.from_v2(mint_normalized)

        deposit = get_deposit_token_deposit_amount(self.settings, mint)
        withdraw = get_deposit_token_withdraw_amount(self.settings, mint)
        assert deposit.normalized() == self._ref_deposit(mint_normalized)
        assert withdraw.normalized() == self._ref_withdraw(mint_normalized)

        # a float intermediate cannot hold this many significant digits, so it disagrees with the exact result.
        float_based = int(mint_normalized * self._numerator / self._denominator)
        assert float_based != mint_normalized * self._numerator // self._denominator

    def test_mint_then_melt_dust_asymmetry(self) -> None:
        """Minting then melting a non-cent-aligned amount retains one cent (deposit ceil exceeds withdraw floor by
        a cent); for a cent-aligned amount the round trip is neutral."""
        non_aligned = UnsignedAmount.from_v2(1005 * 10 ** 15)  # 1% = 0.01005, not a whole cent
        deposit = get_deposit_token_deposit_amount(self.settings, non_aligned)
        withdraw = get_deposit_token_withdraw_amount(self.settings, non_aligned)
        assert deposit.normalized() - withdraw.normalized() == ONE_V2_CENT

        aligned = UnsignedAmount.from_v2(ONE_V2_TOKEN)  # 1% = 0.01, exactly a whole cent
        deposit_aligned = get_deposit_token_deposit_amount(self.settings, aligned)
        withdraw_aligned = get_deposit_token_withdraw_amount(self.settings, aligned)
        assert deposit_aligned.normalized() == withdraw_aligned.normalized()

    # -- deposit (mint) rejections --------------------------------------------------------------------------

    def test_v2_deposit_insufficient_htr_rejected(self) -> None:
        """A V2 mint that locks less HTR than required is rejected: consuming too little HTR for the amount
        minted manifests as a surplus of HTR."""
        tk = self._build_v2_token('2.0 TK')
        token_index = self._output_index(tk, token_data=1, authority=False)
        # mint one more whole token (raising the required deposit by a cent) without locking more HTR
        bumped = UnsignedAmount.from_v2(tk.outputs[token_index].value.raw() + ONE_V2_TOKEN)
        tk.outputs[token_index].value = bumped
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(tk)

    def test_v2_deposit_excess_htr_rejected(self) -> None:
        """A V2 mint that locks more HTR than required is rejected: consuming too much HTR for the amount minted
        manifests as a deficit of HTR."""
        tk = self._build_v2_token('2.0 TK')
        token_index = self._output_index(tk, token_data=1, authority=False)
        # mint one fewer whole token (lowering the required deposit by a cent) while still locking the same HTR
        lowered = UnsignedAmount.from_v2(tk.outputs[token_index].value.raw() - ONE_V2_TOKEN)
        tk.outputs[token_index].value = lowered
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid deficit of HTR.")):
            self._verify_balance(tk)
