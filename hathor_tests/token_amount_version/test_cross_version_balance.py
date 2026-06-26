# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Sum-of-inputs == sum-of-outputs balance verification when V1 and V2 amounts mix. The heart of the project.

Amounts are compared in their shared `normalized()` form, so a V1 input (2 decimal places) and a V2 output
(18 decimal places) balance whenever their normalized values are equal, even though their raw values differ
by the `10**16` normalization factor. These tests drive that property through the DAG builder for the
accepting cases, and through the balance verifier directly for the rejecting cases (the builder always emits
a balanced tx, so an unbalanced one is produced by mutating a built tx's output and re-running the check).
"""

from __future__ import annotations

import re

import pytest
from htr_lib import UnsignedAmount

from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import InputOutputMismatch, InvalidOutputValue
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.serialization.encoding.output_value import get_max_output_value_v2
from hathorlib.token_amount_version import TokenAmountVersion

# One V2 "cent" in normalized units: the smallest amount representable in V1 (10**-2) expressed at V2's
# 18-decimal scale. A V2 amount that is not a multiple of this is "sub-cent" and has no V1 representation.
ONE_V2_CENT = 10 ** 16


class TestCrossVersionBalance(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.tx_verifier = self.manager.verification_service.verifiers.tx

    def _verify_balance(self, tx: Transaction) -> None:
        """Run only the input/output balance check on `tx`, reading its (possibly mutated) outputs directly.

        This isolates `verify_transparent_balance` from script verification, which runs earlier in the full
        pipeline and would reject a mutated tx on its now-stale input signatures before the balance is reached.
        """
        params = self.get_verification_params(self.manager)
        block_storage = self.manager.verification_service._get_block_storage(params)
        token_dict = tx.get_complete_token_info(block_storage)
        self.tx_verifier.verify_transparent_balance(self.manager._settings, tx, token_dict)

    def test_v1_input_v1_output_balances(self) -> None:
        """Baseline control: a V1 tx spends a V1 HTR utxo with V1 outputs summing equal; it verifies."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_v2_input_v2_output_balances(self) -> None:
        """Baseline control: a V2 tx spends a V2 HTR utxo with V2 outputs summing equal; it verifies."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< src
            src.out[0] = 1.00 HTR
            src.token_amount_version = V2

            src.out[0] <<< tx
            tx.out[0] = 1.00 HTR
            tx.token_amount_version = V2

            b11 < src
            b12 < tx
            src <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert tx.get_token_amount_version() == TokenAmountVersion.V2
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_v1_input_v2_output_balances(self) -> None:
        """A V2 tx spends a V1-created HTR utxo (the block reward is always V1) and emits a V2 output of equal
        normalized value; verification passes. Proves inputs/outputs are compared normalized across versions."""
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
        b1 = artifacts.get_typed_vertex('b1', Block)

        assert b1.outputs[0].value.is_v1()
        assert tx.get_token_amount_version() == TokenAmountVersion.V2
        assert tx.outputs[0].value.is_v2()
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_v2_input_v1_output_balances(self) -> None:
        """A V1 tx spends a cent-aligned V2-created HTR utxo and emits an equal V1 output; it balances and
        verifies. Confirms a V1 spending tx normalizes a V2 input correctly."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< src
            src.out[0] = 1.00 HTR
            src.token_amount_version = V2

            src.out[0] <<< tx
            tx.out[0] = 1.00 HTR

            b11 < src
            b12 < tx
            src <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        src = artifacts.get_typed_vertex('src', Transaction)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert src.outputs[0].value.is_v2()
        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        assert tx.outputs[0].value.is_v1()
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_balance_compares_normalized_not_raw(self) -> None:
        """A V1 input (raw 100) and a single V2 output of equal normalized value (raw 10**18) balance, even
        though their raw values differ by the normalization factor. Guards against raw-integer comparison."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< src
            src.out[0] = 1.00 HTR

            src.out[0] <<< tx
            tx.out[0] = 1.00 HTR
            tx.token_amount_version = V2

            b11 < src
            b12 < tx
            src <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        src = artifacts.get_typed_vertex('src', Transaction)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        # The raw representations differ by the 10**16 normalization factor, yet the normalized values match.
        assert src.outputs[0].value.raw() == 100
        assert tx.outputs[0].value.raw() == 100 * UnsignedAmount.get_normalization_factor()
        assert src.outputs[0].value.normalized() == tx.outputs[0].value.normalized()
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_mixed_v1_and_v2_inputs_same_token_summed(self) -> None:
        """A tx spends two HTR utxos of the same token, one created by a V1 tx and one by a V2 tx, and outputs
        their combined normalized total; balance passes. Confirms per-token aggregation across input versions."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..14]
            b10 < dummy

            b1.out[0] <<< src_v1
            src_v1.out[0] = 1.00 HTR

            b2.out[0] <<< src_v2
            src_v2.out[0] = 1.00 HTR
            src_v2.token_amount_version = V2

            src_v1.out[0] <<< tx
            src_v2.out[0] <<< tx
            tx.out[0] = 2.00 HTR

            b11 < src_v1
            b12 < src_v2
            b13 < tx
            src_v1 <-- src_v2 <-- tx <-- b14
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert len(tx.inputs) == 2
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_cross_version_surplus_rejected(self) -> None:
        """A V2 tx spends a 1.00 V1 HTR utxo but emits one V2 raw unit too much; balance verification raises
        `InputOutputMismatch` reporting a surplus. Off-by-one at the finest V2 unit across versions."""
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

        # emit one raw V2 unit more than the input provides -> surplus
        tx.outputs[0].value = UnsignedAmount.from_v2(tx.outputs[0].value.raw() + 1)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(tx)

    def test_cross_version_deficit_rejected(self) -> None:
        """Same setup but one V2 raw unit too little; balance verification raises `InputOutputMismatch`
        reporting a deficit. Pins deficit detection at normalized granularity."""
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

        # emit one raw V2 unit less than the input provides -> deficit
        tx.outputs[0].value = UnsignedAmount.from_v2(tx.outputs[0].value.raw() - 1)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid deficit of HTR.")):
            self._verify_balance(tx)

    def test_v2_tx_splits_htr_into_sub_cent_outputs(self) -> None:
        """A V2 tx spends a 1.00 V1 HTR input and emits 0.005 + 0.995 (one sub-cent output, not V1-representable);
        balance passes. Establishes that sub-cent V2 utxos can be created from V1 funds."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 0.005 HTR
            tx.out[1] = 0.995 HTR
            tx.token_amount_version = V2

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        # 0.005 is half a cent: not a multiple of ONE_V2_CENT, so it has no V1 representation.
        assert tx.outputs[0].value.normalized() == ONE_V2_CENT // 2
        assert tx.outputs[0].value.normalized() % ONE_V2_CENT != 0
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_v1_tx_cannot_spend_single_sub_cent_v2_utxo(self) -> None:
        """A V1 tx spending only a 0.005 sub-cent V2 HTR utxo has no valid output set: a V1 output is cent-granular,
        so a 0.00 output is rejected as non-positive and the smallest positive one (0.01) overspends the 0.005
        input, raising `InputOutputMismatch` for the surplus."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< src
            src.out[0] = 0.005 HTR
            src.out[1] = 0.995 HTR
            src.token_amount_version = V2

            src.out[0] <<< tx
            tx.out[0] = 0.005 HTR
            tx.token_amount_version = V2

            b11 < src
            b12 < tx
            src <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)
        assert tx.outputs[0].value.normalized() == ONE_V2_CENT // 2

        # Re-cast the spend as a V1 tx: the smallest positive V1 output is 0.01, which exceeds the 0.005 input.
        tx.outputs[0].value = UnsignedAmount.from_v1(1)
        with pytest.raises(InputOutputMismatch, match=re.escape("There's an invalid surplus of HTR.")):
            self._verify_balance(tx)

    def test_v1_tx_combining_two_sub_cent_v2_utxos_balances(self) -> None:
        """A V1 tx spends two 0.005 V2 HTR utxos (total 0.01, cent-aligned) into a single V1 0.01 output; it
        balances. Pins that sub-cent V2 dust consolidates into a V1 tx when the total is cent-aligned."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< src
            src.out[0] = 0.005 HTR
            src.out[1] = 0.005 HTR
            src.out[2] = 0.99 HTR
            src.token_amount_version = V2

            src.out[0] <<< tx
            src.out[1] <<< tx
            tx.out[0] = 0.01 HTR

            b11 < src
            b12 < tx
            src <-- tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        assert tx.outputs[0].value.raw() == 1  # 0.01 in V1 cents
        assert len(tx.inputs) == 2
        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_multi_token_mixed_versions_each_balanced_independently(self) -> None:
        """A tx moves HTR and a custom token, spending a V1 utxo of one and a V2 utxo of the other; each token's
        normalized sum balances in its own `TokenInfo` entry and the tx verifies."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..14]
            b10 < dummy

            b1.out[0] <<< src_htr
            src_htr.out[0] = 1.00 HTR

            tka.out[0] = 50 TKA
            tka.token_amount_version = V2
            TKA.token_amount_version = V2

            src_htr.out[0] <<< tx
            tka.out[0] <<< tx
            tx.out[0] = 1.00 HTR
            tx.out[1] = 50 TKA
            tx.token_amount_version = V2

            b11 < src_htr
            b12 < tka
            b13 < tx
            src_htr <-- tka <-- tx <-- b14
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)

        assert tx.get_metadata().validation.is_valid()
        assert tx.get_metadata().voided_by is None

    def test_zero_value_output_rejected_in_both_versions(self) -> None:
        """A V1 output of raw 0 and a V2 output of normalized 0 each raise `InvalidOutputValue`. Pins the
        positivity guard is version-agnostic (it compares against `UnsignedAmount.zero()`)."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)
        vertex_verifier = self.manager.verification_service.verifiers.vertex

        tx.outputs[0].value = UnsignedAmount.from_v1(0)
        with pytest.raises(InvalidOutputValue, match=re.escape('Output value must be a positive integer.')):
            vertex_verifier.verify_outputs(tx)

        tx.outputs[0].value = UnsignedAmount.from_v2(0)
        with pytest.raises(InvalidOutputValue, match=re.escape('Output value must be a positive integer.')):
            vertex_verifier.verify_outputs(tx)

    def test_v2_max_output_value_boundary(self) -> None:
        """A V2 output at `get_max_output_value_v2()` (`2**63 * 10**16`) serializes, while one unit beyond raises
        `ValueError: value is too big` at encoding time. Pins the V2 ceiling, distinct from V1's `2**63`."""
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
        max_value = get_max_output_value_v2()

        # At the ceiling the value encodes. The amount type itself does not bound construction; the ceiling is
        # enforced by the output-value encoding, so the boundary is exercised through serialization.
        tx.outputs[0].value = UnsignedAmount.from_v2(max_value)
        assert len(tx.get_struct()) > 0

        tx.outputs[0].value = UnsignedAmount.from_v2(max_value + 1)
        with pytest.raises(ValueError, match=re.escape(f'value is too big; max is {max_value}')):
            tx.get_struct()
