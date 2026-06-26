# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Fee-based token (FBT) economics under V2 token amounts.

A fee-based token charges a flat per-output fee (`FEE_PER_OUTPUT_V1`, one V1 cent) for every non-authority
output it appears in, and locks no HTR deposit. The fee is expressed as a native-HTR amount, so under
V2 it normalizes to the same `0.01 HTR` a V1 tx pays: the fee-header total and the expected fee are both
compared in `normalized()` units, making the comparison independent of the tx's token amount version. A fee may
be paid in HTR or in a deposit token (never in a fee-based token), and a deposit-token payment costs
`FEE_DIVISOR` deposit-token units per fee unit, since melting that many deposit-token units frees exactly one
fee unit of HTR.

These tests drive the accepting cases through the DAG builder and direct balance verification, and the rejecting
cases by mutating a built tx's fee header (or output) and re-running the balance verifier directly (mutation
invalidates the input scripts, which the full pipeline checks before the balance), plus one end-to-end
propagation for the fee-payment-token prohibition, which is raised during full validation.
"""

from __future__ import annotations

import re

import pytest
from htr_lib import SignedAmount, UnsignedAmount

from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch
from hathor.transaction.headers.fee_header import FeeHeaderEntry
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfoDict
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.token_info import TokenVersion

# One V2 "cent" in normalized units: the smallest amount representable in V1 (10**-2) written at V2's
# 18-decimal scale. The per-output fee is exactly this amount of HTR.
ONE_V2_CENT = 10 ** 16


class TestFeeTokensV2(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.settings = self.manager._settings
        self.tx_verifier = self.manager.verification_service.verifiers.tx
        self.htr_uid = self.settings.HATHOR_TOKEN_UID

    # -- helpers --------------------------------------------------------------------------------------------

    def _token_dict(self, tx: Transaction) -> TokenInfoDict:
        params = self.get_verification_params(self.manager)
        block_storage = self.manager.verification_service._get_block_storage(params)
        return tx.get_complete_token_info(block_storage)

    def _verify_balance(self, tx: Transaction) -> None:
        """Run only the input/output balance check, reading the tx's (possibly mutated) fee header directly."""
        self.tx_verifier.verify_transparent_balance(self.settings, tx, self._token_dict(tx))

    def _spent_output(self, tx_input: TxInput) -> TxOutput:
        """The `TxOutput` a given input spends."""
        return self.manager.tx_storage.get_transaction(tx_input.tx_id).outputs[tx_input.index]

    def _spent_token_uid(self, tx_input: TxInput) -> bytes:
        """The token uid of the output a given input spends."""
        spent_tx = self.manager.tx_storage.get_transaction(tx_input.tx_id)
        return spent_tx.get_token_uid(spent_tx.outputs[tx_input.index].get_token_index())

    def test_fee_token_creation_charges_normalized_fee_v2(self) -> None:
        """A V2 fee-based token-creation tx minting one output charges the per-output fee normalized to V2 (e.g.
        `0.01 HTR`); assert the tx verifies. Pins fee normalization under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR

            mint_tx.out[0] = 5.0 FBT
            mint_tx.token_amount_version = V2
            mint_tx.fee = 0.01 HTR

            b11 < mint_tx
            mint_tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        fbt = artifacts.get_typed_vertex('FBT', TokenCreationTransaction)

        assert fbt.get_token_amount_version() == TokenAmountVersion.V2
        assert fbt.token_version == TokenVersion.FEE
        # the single minted output charges exactly one V2-normalized cent of HTR, and it is the expected fee.
        token_dict = self._token_dict(fbt)
        assert fbt.get_fee_header().total_fee_amount().normalized() == ONE_V2_CENT
        assert token_dict.calculate_fee(self.settings).normalized() == ONE_V2_CENT
        assert fbt.get_metadata().validation.is_valid()
        assert fbt.get_metadata().voided_by is None

    def test_v1_and_v2_fee_encodings_yield_same_normalized_fee(self) -> None:
        """Two equivalent fee txs, one V1 (fee spelled `1`) and one V2 (fee spelled as the normalized equivalent),
        both representing `0.01 HTR`; assert both produce the same expected fee and verify. Confirms fee comparison
        is version-independent."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..20]
            b15 < dummy

            FA.token_version = fee
            FA.fee = 1 HTR
            mint_a.out[0] = 5 FA
            mint_a.fee = 1 HTR

            FB.token_version = fee
            FB.token_amount_version = V2
            FB.fee = {ONE_V2_CENT} HTR
            mint_b.out[0] = 5.0 FB
            mint_b.token_amount_version = V2
            mint_b.fee = {ONE_V2_CENT} HTR

            b16 < mint_a
            b17 < mint_b
            mint_a <-- mint_b <-- b18
        ''')
        artifacts.propagate_with(self.manager)
        fa = artifacts.get_typed_vertex('FA', TokenCreationTransaction)
        fb = artifacts.get_typed_vertex('FB', TokenCreationTransaction)

        assert fa.get_token_amount_version() == TokenAmountVersion.V1
        assert fb.get_token_amount_version() == TokenAmountVersion.V2

        # the V1 fee (spelled `1`) and the V2 fee (spelled `10**16`, the normalized equivalent) both mean 0.01 HTR.
        assert fa.get_fee_header().total_fee_amount().normalized() == ONE_V2_CENT
        assert fb.get_fee_header().total_fee_amount().normalized() == ONE_V2_CENT
        assert self._token_dict(fa).calculate_fee(self.settings).normalized() == ONE_V2_CENT
        assert self._token_dict(fb).calculate_fee(self.settings).normalized() == ONE_V2_CENT

        for tx in (fa, fb):
            assert tx.get_metadata().validation.is_valid()
            assert tx.get_metadata().voided_by is None

    def test_v2_fee_mismatch_rejected(self) -> None:
        """A V2 tx whose fee-header total differs from the expected fee raises `InputOutputMismatch('Fee amount is
        different than expected. (amount=..., expected=...)')`. Pins the fee-mismatch exception under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR

            mint_tx.out[0] = 5.0 FBT
            mint_tx.token_amount_version = V2
            mint_tx.fee = 0.01 HTR

            b11 < mint_tx
            mint_tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        mint_tx = artifacts.get_typed_vertex('mint_tx', Transaction)

        # replace the exact 0.01 HTR fee with a sub-cent 0.005 HTR fee, only expressible under V2.
        mint_tx.get_fee_header().fees = [
            FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v2(ONE_V2_CENT // 2))
        ]
        with pytest.raises(
            InputOutputMismatch,
            match=re.escape('Fee amount is different than expected. (amount=0.005, expected=0.01)'),
        ):
            self._verify_balance(mint_tx)

    def test_v2_fee_paid_with_v1_htr_input(self) -> None:
        """A V2 tx pays its fee from a V1-created HTR utxo; assert the fee-header total normalizes against the V1
        input and verification passes. Mixing on the fee path."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..14]
            b10 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR
            mint_fbt.out[0] = 5.0 FBT
            mint_fbt.token_amount_version = V2
            mint_fbt.fee = 0.01 HTR

            b1.out[0] <<< tx
            mint_fbt.out[0] <<< tx
            tx.out[0] = 5.0 FBT
            tx.token_amount_version = V2
            tx.fee = 0.01 HTR

            b11 < mint_fbt
            b12 < tx
            mint_fbt <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        # the HTR input funding the fee is the block reward at b1, which is always V1.
        htr_input = next(inp for inp in tx.inputs if self._spent_token_uid(inp) == self.htr_uid)
        assert self._spent_output(htr_input).value.is_v1()

        assert tx.get_token_amount_version() == TokenAmountVersion.V2
        assert tx.get_fee_header().total_fee_amount().normalized() == ONE_V2_CENT
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_fee_added_to_balance_normalized_v2(self) -> None:
        """A V2 tx with a fee header contributes the fee to the token's balance sum in normalized units; an
        off-by-one fee is rejected. Pins fee-into-balance accounting under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR

            mint_tx.out[0] = 5.0 FBT
            mint_tx.token_amount_version = V2
            mint_tx.fee = 0.01 HTR

            b11 < mint_tx
            mint_tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        mint_tx = artifacts.get_typed_vertex('mint_tx', Transaction)

        # the 0.01 HTR input exactly funds the 0.01 HTR fee: the fee, summed into the HTR balance, nets to zero.
        token_dict = self._token_dict(mint_tx)
        assert token_dict.fees_from_fee_header.normalized() == ONE_V2_CENT
        assert token_dict[self.htr_uid].amount == SignedAmount()

        # raising the fee by one raw V2 unit leaves that unit unbacked by any HTR input: a surplus.
        mint_tx.get_fee_header().fees = [
            FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v2(ONE_V2_CENT + 1))
        ]
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(mint_tx)

    def test_fee_paid_with_deposit_token_costs_fee_divisor_per_unit_v2(self) -> None:
        """Paying an FBT fee with a deposit token requires `FEE_DIVISOR` deposit-token units per fee unit under V2;
        assert the matching fee-header entry is accepted. Pins the deposit-token-denominated fee."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..20]
            b15 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR
            mint_fbt.out[0] = 5.0 FBT
            mint_fbt.token_amount_version = V2
            mint_fbt.fee = 0.01 HTR

            DBT.token_amount_version = V2
            mint_dbt.out[0] = 10.0 DBT
            mint_dbt.token_amount_version = V2

            mint_fbt.out[0] <<< tx
            mint_dbt.out[0] <<< tx
            tx.out[0] = 5.0 FBT
            tx.out[1] = 9.0 DBT
            tx.token_amount_version = V2
            tx.fee = 1.0 DBT

            b16 < mint_fbt
            b17 < mint_dbt
            b18 < tx
            mint_fbt <-- mint_dbt <-- tx <-- b19
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)
        dbt = artifacts.get_typed_vertex('DBT', TokenCreationTransaction)

        fees = tx.get_fee_header().fees
        assert len(fees) == 1
        # the single fee entry pays in the deposit token DBT, not HTR.
        assert tx.get_token_uid(fees[0].token_index) == dbt.hash
        # one fee unit (0.01 HTR) costs FEE_DIVISOR deposit-token units, i.e. FEE_DIVISOR cents of DBT.
        assert fees[0].amount.normalized() == self.settings.FEE_DIVISOR * ONE_V2_CENT
        # melting those deposit-token units frees exactly one fee unit of HTR.
        assert tx.get_fee_header().total_fee_amount().normalized() == ONE_V2_CENT
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_fbt_cannot_pay_its_own_fee_v2(self) -> None:
        """A V2 tx attempting to pay an FBT fee in that same fee-based token fails full validation with the
        `token {uid} cannot be used to pay fees` message. Pins the FBT-as-payment prohibition under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..15]
            b10 < dummy

            FBT.token_version = fee
            FBT.token_amount_version = V2
            FBT.fee = 0.01 HTR

            tx1.out[0] = 1.23 FBT
            tx1.token_amount_version = V2
            tx1.fee = 1.0 FBT
        ''')
        fbt = artifacts.get_typed_vertex('FBT', TokenCreationTransaction)
        # the fee-based token creation itself, paying its per-output fee in HTR, is valid.
        artifacts.propagate_with(self.manager, up_to='FBT')

        with pytest.raises(Exception) as exc_info:
            artifacts.propagate_with(self.manager, up_to='tx1')
        cause = exc_info.value.__cause__
        assert isinstance(cause, InvalidNewTransaction)
        assert cause.args[0] == f'full validation failed: token {fbt.hash_hex} cannot be used to pay fees'
