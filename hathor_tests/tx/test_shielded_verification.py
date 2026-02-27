# Copyright 2024 Hathor Labs
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

"""Tests for the ShieldedTransactionVerifier."""

import os
from unittest.mock import MagicMock

import hathor_ct_crypto as lib
import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import (
    InvalidRangeProofError,
    InvalidShieldedOutputError,
    InvalidSurjectionProofError,
    ShieldedAuthorityError,
    ShieldedBalanceMismatchError,
    TrivialCommitmentError,
)
from hathor.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
)
from hathor.verification.shielded_transaction_verifier import ShieldedTransactionVerifier


def _make_settings() -> HathorSettings:
    """Create minimal HathorSettings for tests."""
    settings = MagicMock(spec=HathorSettings)
    settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT = 1
    settings.FEE_PER_FULL_SHIELDED_OUTPUT = 2
    return settings


def _make_verifier() -> ShieldedTransactionVerifier:
    return ShieldedTransactionVerifier(settings=_make_settings())


def _make_amount_shielded(amount: int = 1000, token_data: int = 0) -> AmountShieldedOutput:
    """Create a valid AmountShieldedOutput with proper crypto."""
    gen = lib.htr_asset_tag()
    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, gen)
    range_proof = lib.create_range_proof(amount, blinding, commitment, gen)
    script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'
    return AmountShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        token_data=token_data,
    )


def _make_full_shielded(amount: int = 500, token_uid: bytes = bytes(32)) -> FullShieldedOutput:
    """Create a valid FullShieldedOutput with proper crypto."""
    raw_tag = lib.derive_tag(token_uid)
    asset_bf = os.urandom(32)
    asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)

    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, asset_comm)
    range_proof = lib.create_range_proof(amount, blinding, commitment, asset_comm)

    input_gen = lib.derive_asset_tag(token_uid)
    surjection_proof = lib.create_surjection_proof(
        raw_tag, asset_bf, [(input_gen, raw_tag, bytes(32))]
    )

    script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'
    return FullShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        asset_commitment=asset_comm,
        surjection_proof=surjection_proof,
    )


def _mock_tx(
    shielded_outputs: list,
    token_uid: bytes = bytes(32),
    fee_amount: int = 0,
) -> MagicMock:
    """Create a mock Transaction with shielded outputs."""
    from hathor.transaction.headers.fee_header import FeeEntry

    tx = MagicMock()
    tx.shielded_outputs = shielded_outputs
    tx.outputs = []
    tx.inputs = []
    tx.tokens = []
    tx.get_token_uid = MagicMock(return_value=token_uid)
    if fee_amount > 0:
        fee_header = MagicMock()
        fee_header.total_fee_amount = MagicMock(return_value=fee_amount)
        fee_header.get_fees = MagicMock(return_value=[
            FeeEntry(token_uid=b'\x00' * 32, amount=fee_amount),
        ])
        tx.has_fees = MagicMock(return_value=True)
        tx.get_fee_header = MagicMock(return_value=fee_header)
    else:
        tx.has_fees = MagicMock(return_value=False)
    return tx


class TestCommitmentsValid:
    def test_valid_amount_shielded(self) -> None:
        verifier = _make_verifier()
        output = _make_amount_shielded()
        tx = _mock_tx([output])
        verifier.verify_commitments_valid(tx)

    def test_valid_full_shielded(self) -> None:
        verifier = _make_verifier()
        output = _make_full_shielded()
        tx = _mock_tx([output])
        verifier.verify_commitments_valid(tx)

    def test_invalid_commitment_size(self) -> None:
        verifier = _make_verifier()
        output = AmountShieldedOutput(
            commitment=b'\x00' * 10,  # Wrong size
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            token_data=0,
        )
        tx = _mock_tx([output])
        with pytest.raises(InvalidShieldedOutputError, match='commitment must be'):
            verifier.verify_commitments_valid(tx)

    def test_invalid_asset_commitment_size(self) -> None:
        verifier = _make_verifier()
        # Use a valid commitment (must pass curve point validation)
        valid_output = _make_amount_shielded()
        output = FullShieldedOutput(
            commitment=valid_output.commitment,
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            asset_commitment=b'\x00' * 10,  # Wrong size
            surjection_proof=b'\x00' * 50,
        )
        tx = _mock_tx([output])
        with pytest.raises(InvalidShieldedOutputError, match='asset_commitment must be'):
            verifier.verify_commitments_valid(tx)

    def test_multiple_outputs_all_valid(self) -> None:
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        verifier.verify_commitments_valid(tx)


class TestRangeProofs:
    def test_valid_amount_shielded_range_proof(self) -> None:
        verifier = _make_verifier()
        output = _make_amount_shielded(amount=42)
        tx = _mock_tx([output])
        verifier.verify_range_proofs(tx)

    def test_valid_full_shielded_range_proof(self) -> None:
        verifier = _make_verifier()
        output = _make_full_shielded(amount=42)
        tx = _mock_tx([output])
        verifier.verify_range_proofs(tx)

    def test_invalid_range_proof(self) -> None:
        verifier = _make_verifier()
        # Create a valid output then corrupt the range proof
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 1000
        commitment = lib.create_commitment(amount, blinding, gen)
        range_proof = lib.create_range_proof(amount, blinding, commitment, gen)
        # Corrupt by flipping a byte
        corrupted_proof_arr = bytearray(range_proof)
        corrupted_proof_arr[10] ^= 0xFF
        corrupted_proof = bytes(corrupted_proof_arr)

        output = AmountShieldedOutput(
            commitment=commitment,
            range_proof=corrupted_proof,
            script=b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac',
            token_data=0,
        )
        tx = _mock_tx([output])
        with pytest.raises(InvalidRangeProofError, match='range proof verification failed'):
            verifier.verify_range_proofs(tx)

    def test_wrong_generator_fails(self) -> None:
        """Range proof created with one generator, verified with another."""
        verifier = _make_verifier()
        # Create with HTR generator
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 100
        commitment = lib.create_commitment(amount, blinding, gen)
        range_proof = lib.create_range_proof(amount, blinding, commitment, gen)

        output = AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac',
            token_data=1,  # token_data=1 means custom token
        )
        # When token_data=1, get_token_uid returns a different token
        different_uid = b'\x01' + bytes(31)
        tx = _mock_tx([output], token_uid=different_uid)
        tx.tokens = [different_uid]  # Need at least 1 token for bounds check
        with pytest.raises(InvalidRangeProofError):
            verifier.verify_range_proofs(tx)

    def test_multiple_outputs_all_valid_proofs(self) -> None:
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        verifier.verify_range_proofs(tx)


class TestAuthorityRestriction:
    def test_normal_output_allowed(self) -> None:
        verifier = _make_verifier()
        output = _make_amount_shielded(token_data=0)
        tx = _mock_tx([output])
        verifier.verify_authority_restriction(tx)

    def test_authority_mint_rejected(self) -> None:
        verifier = _make_verifier()
        from hathor.transaction import TxOutput

        # token_data with authority bit set (mint)
        authority_token_data = TxOutput.TOKEN_AUTHORITY_MASK | 1
        output = AmountShieldedOutput(
            commitment=b'\x00' * COMMITMENT_SIZE,
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            token_data=authority_token_data,
        )
        tx = _mock_tx([output])
        with pytest.raises(ShieldedAuthorityError, match='authority outputs cannot be shielded'):
            verifier.verify_authority_restriction(tx)

    def test_authority_melt_rejected(self) -> None:
        verifier = _make_verifier()
        from hathor.transaction import TxOutput
        authority_token_data = TxOutput.TOKEN_AUTHORITY_MASK | 2
        output = AmountShieldedOutput(
            commitment=b'\x00' * COMMITMENT_SIZE,
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            token_data=authority_token_data,
        )
        tx = _mock_tx([output])
        with pytest.raises(ShieldedAuthorityError):
            verifier.verify_authority_restriction(tx)

    def test_full_shielded_skips_authority_check(self) -> None:
        """FullShieldedOutput has no token_data, so authority check doesn't apply."""
        verifier = _make_verifier()
        output = _make_full_shielded()
        tx = _mock_tx([output])
        # Should not raise — FullShieldedOutput doesn't have token_data
        verifier.verify_authority_restriction(tx)


class TestTrivialCommitmentProtection:
    def test_no_shielded_outputs_passes(self) -> None:
        verifier = _make_verifier()
        tx = _mock_tx([])
        verifier.verify_trivial_commitment_protection(tx)

    def test_single_shielded_output_fails(self) -> None:
        """Rule 4: If all inputs are transparent, need >= 2 shielded outputs."""
        verifier = _make_verifier()
        output = _make_amount_shielded()
        tx = _mock_tx([output])
        tx.inputs = []  # all transparent (no inputs)
        with pytest.raises(TrivialCommitmentError, match='at least 2 shielded outputs'):
            verifier.verify_trivial_commitment_protection(tx)

    def test_two_shielded_outputs_passes(self) -> None:
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        tx.inputs = []
        verifier.verify_trivial_commitment_protection(tx)

    def test_mixed_types_two_outputs_passes(self) -> None:
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        tx.inputs = []
        verifier.verify_trivial_commitment_protection(tx)


class TestVerifyShieldedOutputs:
    def test_top_level_calls_all_checks(self) -> None:
        """verify_shielded_outputs should call all sub-verifications."""
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        # fee_amount=2 covers 2 AmountShieldedOutputs at 1 each
        tx = _mock_tx([o1, o2], fee_amount=2)
        # Should not raise
        verifier.verify_shielded_outputs(tx)

    def test_top_level_rejects_invalid(self) -> None:
        verifier = _make_verifier()
        output = AmountShieldedOutput(
            commitment=b'\x00' * 10,  # invalid size
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            token_data=0,
        )
        tx = _mock_tx([output])
        with pytest.raises(InvalidShieldedOutputError):
            verifier.verify_shielded_outputs(tx)


class TestBalanceVerification:
    def test_transparent_balance_correct(self) -> None:
        """Verify balance with only transparent inputs/outputs."""
        verifier = _make_verifier()

        tx = MagicMock()
        tx.shielded_outputs = []
        tx.outputs = []
        tx.inputs = []
        tx.has_fees = MagicMock(return_value=False)

        # No shielded outputs, no transparent outputs → trivially balanced
        verifier.verify_shielded_balance(tx)

    def test_balanced_transparent_io(self) -> None:
        """Transparent 1000 in → transparent 1000 out, balanced."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        # Mock transparent input
        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.value = 1000
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_output.is_token_authority = MagicMock(return_value=False)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        # Mock transparent output
        tx_output = MagicMock()
        tx_output.value = 1000
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=False)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        verifier.verify_shielded_balance(tx)

    def test_balance_mismatch_raises(self) -> None:
        """Transparent 1000 in → transparent 500 out → balance mismatch."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.value = 1000
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_output.is_token_authority = MagicMock(return_value=False)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx_output = MagicMock()
        tx_output.value = 500  # Mismatched
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=False)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(ShieldedBalanceMismatchError):
            verifier.verify_shielded_balance(tx)

    def test_transparent_with_fee(self) -> None:
        """Transparent 1000 in → transparent 900 out + 100 fee, balanced."""
        from hathor.transaction.headers.fee_header import FeeEntry

        verifier = _make_verifier()
        token_uid = bytes(32)

        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.value = 1000
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_output.is_token_authority = MagicMock(return_value=False)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx_output = MagicMock()
        tx_output.value = 900
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        fee_header = MagicMock()
        fee_header.get_fees = MagicMock(return_value=[
            FeeEntry(token_uid=token_uid, amount=100),
        ])

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=True)
        tx.get_fee_header = MagicMock(return_value=fee_header)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        verifier.verify_shielded_balance(tx)


class TestSurjectionProofs:
    def test_amount_shielded_no_surjection_needed(self) -> None:
        """AmountShieldedOutput doesn't require surjection proof."""
        verifier = _make_verifier()
        output = _make_amount_shielded()
        tx = _mock_tx([output])
        tx.storage = MagicMock()
        # Should not raise — AmountShieldedOutput skips surjection check
        verifier.verify_surjection_proofs(tx)

    def test_full_shielded_valid_surjection(self) -> None:
        """FullShieldedOutput with valid surjection proof passes."""
        verifier = _make_verifier()
        token_uid = bytes(32)
        output = _make_full_shielded(amount=500, token_uid=token_uid)

        # Mock a transparent input spending the same token
        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_output.value = 500
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.outputs = []
        tx.inputs = [tx_input]
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        verifier.verify_surjection_proofs(tx)

    def test_full_shielded_missing_surjection_fails(self) -> None:
        """FullShieldedOutput without surjection proof fails."""
        verifier = _make_verifier()
        output = FullShieldedOutput(
            commitment=b'\x00' * COMMITMENT_SIZE,
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            asset_commitment=b'\x00' * ASSET_COMMITMENT_SIZE,
            surjection_proof=b'',  # Empty surjection proof
        )

        # Need at least one input to avoid the empty domain check
        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=bytes(32))

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.inputs = [tx_input]
        tx.outputs = []
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(InvalidSurjectionProofError, match='requires surjection proof'):
            verifier.verify_surjection_proofs(tx)

    def test_full_shielded_invalid_surjection_fails(self) -> None:
        """FullShieldedOutput with invalid surjection proof fails."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        # Create a valid output
        raw_tag = lib.derive_tag(token_uid)
        asset_bf = os.urandom(32)
        asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)
        blinding = os.urandom(32)
        commitment = lib.create_commitment(500, blinding, asset_comm)
        range_proof = lib.create_range_proof(500, blinding, commitment, asset_comm)

        # Create valid surjection proof then corrupt it
        input_gen = lib.derive_asset_tag(token_uid)
        surjection_proof = lib.create_surjection_proof(
            raw_tag, asset_bf, [(input_gen, raw_tag, bytes(32))]
        )
        corrupted_arr = bytearray(surjection_proof)
        corrupted_arr[5] ^= 0xFF
        corrupted = bytes(corrupted_arr)

        output = FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac',
            asset_commitment=asset_comm,
            surjection_proof=corrupted,
        )

        # Mock input
        spent_tx = MagicMock()
        spent_output = MagicMock()
        spent_output.get_token_index = MagicMock(return_value=0)
        spent_tx.outputs = [spent_output]
        spent_tx.shielded_outputs = []
        spent_tx.get_token_uid = MagicMock(return_value=token_uid)

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 0

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.outputs = []
        tx.inputs = [tx_input]
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(InvalidSurjectionProofError, match='surjection proof verification failed'):
            verifier.verify_surjection_proofs(tx)


class TestShieldedFee:
    def test_calculate_shielded_fee_amount_only(self) -> None:
        """Two AmountShieldedOutputs → fee = 2 * FEE_PER_AMOUNT_SHIELDED_OUTPUT."""
        settings = _make_settings()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        fee = ShieldedTransactionVerifier.calculate_shielded_fee(settings, tx)
        assert fee == 2 * settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT

    def test_calculate_shielded_fee_full_only(self) -> None:
        """Two FullShieldedOutputs → fee = 2 * FEE_PER_FULL_SHIELDED_OUTPUT."""
        settings = _make_settings()
        o1 = _make_full_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        fee = ShieldedTransactionVerifier.calculate_shielded_fee(settings, tx)
        assert fee == 2 * settings.FEE_PER_FULL_SHIELDED_OUTPUT

    def test_calculate_shielded_fee_mixed(self) -> None:
        """One Amount + one Full → fee = FEE_PER_AMOUNT + FEE_PER_FULL."""
        settings = _make_settings()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        tx = _mock_tx([o1, o2])
        fee = ShieldedTransactionVerifier.calculate_shielded_fee(settings, tx)
        assert fee == settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT + settings.FEE_PER_FULL_SHIELDED_OUTPUT

    def test_verify_shielded_fee_no_fee_header_raises(self) -> None:
        """Shielded tx without fee header raises."""
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        tx = _mock_tx([o1, o2])  # no fee
        with pytest.raises(InvalidShieldedOutputError, match='require a fee header'):
            verifier.verify_shielded_fee(tx)

    def test_verify_shielded_fee_insufficient_fee_raises(self) -> None:
        """Fee declared < shielded fee required → raises."""
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        # Need 1+2=3, declare only 1
        tx = _mock_tx([o1, o2], fee_amount=1)
        with pytest.raises(InvalidShieldedOutputError, match='insufficient fee'):
            verifier.verify_shielded_fee(tx)

    def test_verify_shielded_fee_exact_fee_passes(self) -> None:
        """Fee declared == shielded fee required → passes."""
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_full_shielded(amount=200)
        # Need 1+2=3
        tx = _mock_tx([o1, o2], fee_amount=3)
        verifier.verify_shielded_fee(tx)

    def test_verify_shielded_fee_overpayment_passes(self) -> None:
        """Fee declared > shielded fee required → passes (lower bound only)."""
        verifier = _make_verifier()
        o1 = _make_amount_shielded(amount=100)
        o2 = _make_amount_shielded(amount=200)
        # Need 2, declare 10
        tx = _mock_tx([o1, o2], fee_amount=10)
        verifier.verify_shielded_fee(tx)
