# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Authority (mint/melt) outputs under V2: the value field is a bitmask read via `.raw()`, not a token amount.

An authority output carries its mint/melt capability in the bits of its value field, so that field is read
through `.raw()` no matter the transaction's token amount version. Authority outputs are therefore
version-agnostic: they are excluded from a token's balance sum, their bitmask must stay within
`ALL_AUTHORITIES`, and native HTR may never carry one. A V2 transaction treats them exactly as V1 does. The
accepting cases run through the DAG builder; the rejecting cases mutate a built transaction's outputs and
drive the verifier directly (the builder always emits a balanced, well-formed tx).
"""

from __future__ import annotations

import re

import pytest
from htr_lib import UnsignedAmount

from hathor.transaction import Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.exceptions import InvalidToken
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfoDict
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.token_amount_version import TokenAmountVersion


class TestAuthoritiesV2(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.tx_verifier = self.manager.verification_service.verifiers.tx
        self.vertex_verifier = self.manager.verification_service.verifiers.vertex

    def _token_dict(self, tx: Transaction) -> TokenInfoDict:
        """Build the complete per-token info for `tx`, reading its (possibly mutated) inputs and outputs."""
        params = self.get_verification_params(self.manager)
        block_storage = self.manager.verification_service._get_block_storage(params)
        return tx.get_complete_token_info(block_storage)

    def _verify_balance(self, tx: Transaction) -> None:
        """Run only the input/output balance check on `tx`, reading its (possibly mutated) outputs directly.

        This isolates `verify_transparent_balance` from script verification, which runs earlier in the full
        pipeline and would reject a mutated tx on its now-stale input signatures before the balance is reached.
        """
        token_dict = self._token_dict(tx)
        self.tx_verifier.verify_transparent_balance(self.manager._settings, tx, token_dict)

    def test_authority_output_value_is_bitmask_not_amount_v2(self) -> None:
        """A V2 tx with a mint/melt authority output; assert the authority bits are read via `value.raw()` and the
        output does not contribute to the token's balance sum. Pins authority outputs are version-agnostic."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            spend.out[0] = 100 TKA
            spend.token_amount_version = V2
            TKA.token_amount_version = V2

            b11 < TKA
            b12 < spend
            TKA <-- spend <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)

        assert tka.get_token_amount_version() == TokenAmountVersion.V2

        mint_auth = next(output for output in tka.outputs if output.can_mint_token())
        melt_auth = next(output for output in tka.outputs if output.can_melt_token())
        minted = next(
            output for output in tka.outputs
            if output.get_token_index() == 1 and not output.is_token_authority()
        )

        # The value field holds the capability bitmask, read via `.raw()`, even though the tx is V2.
        assert mint_auth.value.is_v2()
        assert mint_auth.value.raw() == TxOutput.TOKEN_MINT_MASK
        assert mint_auth.can_mint_token()
        assert not mint_auth.can_melt_token()

        assert melt_auth.value.is_v2()
        assert melt_auth.value.raw() == TxOutput.TOKEN_MELT_MASK
        assert melt_auth.can_melt_token()
        assert not melt_auth.can_mint_token()

        # The token's balance sum counts only the minted output; the authority bitmasks (raw 1 and 2) are excluded.
        token_uid = tka.get_token_uid(minted.get_token_index())
        token_info = self._token_dict(tka)[token_uid]
        assert token_info.amount.raw() == minted.value.raw() == 100
        assert token_info.can_mint
        assert token_info.can_melt

        assert tka.get_metadata().validation.is_valid()
        assert tka.get_metadata().voided_by is None

    def test_invalid_authority_bits_rejected_v2(self) -> None:
        """A V2 authority output whose `value.raw()` exceeds `ALL_AUTHORITIES` raises
        `InvalidToken('Invalid authorities in output ...')`. Pins the ceiling check uses `raw()` under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            spend.out[0] = 100 TKA
            spend.token_amount_version = V2
            TKA.token_amount_version = V2

            b11 < TKA
            b12 < spend
            TKA <-- spend <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        spend = artifacts.get_typed_vertex('spend', Transaction)

        # 0b100 sets neither mint nor melt but keeps the authority flag, so it clears the input-capability
        # check and reaches the ceiling check, which compares `raw()` against ALL_AUTHORITIES (0b11).
        assert 0b100 > TxOutput.ALL_AUTHORITIES
        spend.outputs.append(TxOutput(
            value=UnsignedAmount.from_v2(0b100),
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1,
            script=spend.outputs[0].script,
        ))
        with pytest.raises(InvalidToken, match=re.escape('Invalid authorities in output (0b100)')):
            self._verify_balance(spend)

    def test_authority_passthrough_does_not_affect_balance_v2(self) -> None:
        """A V2 tx passes a mint authority through (authority in -> authority out) with no value change; assert
        balance verification ignores authority outputs and the tx verifies."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            spend.out[0] = 100 TKA
            spend.token_amount_version = V2
            TKA.token_amount_version = V2

            b11 < TKA
            b12 < spend
            TKA <-- spend <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)
        spend = artifacts.get_typed_vertex('spend', Transaction)

        # Spend TKA's still-unspent mint authority and re-emit an identical mint authority: capability in,
        # capability out, no value moved.
        mint_auth_index = next(i for i, output in enumerate(tka.outputs) if output.can_mint_token())
        spend.inputs.append(TxInput(tka.hash, mint_auth_index, b''))
        spend.outputs.append(TxOutput(
            value=UnsignedAmount.from_v2(TxOutput.TOKEN_MINT_MASK),
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1,
            script=spend.outputs[0].script,
        ))

        token_uid = tka.hash
        token_info = self._token_dict(spend)[token_uid]
        # The passthrough leaves the token balanced (100 in, 100 out) and carries the mint capability.
        assert token_info.amount.raw() == 0
        assert token_info.can_mint

        # No exception: the authority output is ignored by the balance sum.
        self._verify_balance(spend)

    def test_hathor_authority_output_rejected_v2(self) -> None:
        """A V2 tx with an authority UTXO on native HTR (token_index 0) raises `InvalidToken('Cannot have authority
        UTXO for hathor tokens')`, regardless of version."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR
            tx.token_amount_version = V2

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert tx.get_token_amount_version() == TokenAmountVersion.V2

        # token_index 0 is native HTR; flag the output as a mint authority on it.
        tx.outputs[0].token_data = TxOutput.TOKEN_AUTHORITY_MASK | 0
        tx.outputs[0].value = UnsignedAmount.from_v2(TxOutput.TOKEN_MINT_MASK)
        assert tx.outputs[0].get_token_index() == 0
        assert tx.outputs[0].is_token_authority()
        with pytest.raises(InvalidToken, match=re.escape('Cannot have authority UTXO for hathor tokens')):
            self.vertex_verifier.verify_outputs(tx)
