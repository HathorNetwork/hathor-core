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

"""Adversarial security tests for the shielded outputs feature.

These tests exercise fixes from the security audit:
- ISSUE-01: Feature gate without assert
- ISSUE-02: Invalid shielded input references
- ISSUE-03: MAX_SHIELDED_OUTPUTS enforcement
- ISSUE-04: MAX proof size enforcement in deserialization
- ISSUE-05: Authority outputs in balance equation
- ISSUE-06: Out-of-bounds token_data index
- ISSUE-14: Empty surjection domain
- ISSUE-15: Token UID length validation
- ISSUE-16: Header deserialization type check
"""

import os
import struct
from unittest.mock import MagicMock

import hathor_ct_crypto as lib
import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import InvalidShieldedOutputError, InvalidSurjectionProofError
from hathor.transaction.headers.shielded_outputs_header import ShieldedOutputsHeader
from hathor.transaction.shielded_tx_output import (
    MAX_RANGE_PROOF_SIZE,
    MAX_SHIELDED_OUTPUTS,
    MAX_SURJECTION_PROOF_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    deserialize_shielded_output,
)
from hathor.verification.shielded_transaction_verifier import ShieldedTransactionVerifier


def _make_settings() -> HathorSettings:
    return MagicMock(spec=HathorSettings)


def _make_verifier() -> ShieldedTransactionVerifier:
    return ShieldedTransactionVerifier(settings=_make_settings())


def _make_amount_shielded(amount: int = 1000, token_data: int = 0) -> AmountShieldedOutput:
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


class TestIssue03_MaxShieldedOutputs:
    """ISSUE-03: Enforce MAX_SHIELDED_OUTPUTS limit."""

    def test_too_many_outputs_rejected_by_verifier(self) -> None:
        verifier = _make_verifier()
        outputs = [
            AmountShieldedOutput(
                commitment=b'\x02' + b'\x00' * 32,
                range_proof=b'\x00' * 100,
                script=b'\x00' * 25,
                token_data=0,
            )
            for _ in range(MAX_SHIELDED_OUTPUTS + 1)
        ]
        tx = MagicMock()
        tx.shielded_outputs = outputs
        with pytest.raises(InvalidShieldedOutputError, match='too many shielded outputs'):
            verifier.verify_commitments_valid(tx)

    def test_max_outputs_accepted(self) -> None:
        """Exactly MAX_SHIELDED_OUTPUTS should be accepted (count and commitment check)."""
        verifier = _make_verifier()
        # Use a valid commitment (must pass curve point validation)
        valid_output = _make_amount_shielded()
        outputs = [
            AmountShieldedOutput(
                commitment=valid_output.commitment,
                range_proof=b'\x00' * 100,
                script=b'\x00' * 25,
                token_data=0,
            )
            for _ in range(MAX_SHIELDED_OUTPUTS)
        ]
        tx = MagicMock()
        tx.shielded_outputs = outputs
        # Should not raise on count alone (may raise on proof verification later)
        verifier.verify_commitments_valid(tx)


class TestIssue04_MaxProofSizes:
    """ISSUE-04: Reject oversized proofs during deserialization."""

    def test_oversized_range_proof_rejected(self) -> None:
        """Range proof exceeding MAX_RANGE_PROOF_SIZE should be rejected."""
        oversized_rp = b'\x00' * (MAX_RANGE_PROOF_SIZE + 1)
        # Build a minimal serialized AmountShieldedOutput with oversized range proof
        buf = struct.pack('!B', OutputMode.AMOUNT_ONLY)
        buf += b'\x02' + b'\x00' * 32  # commitment (33 bytes)
        buf += struct.pack('!H', len(oversized_rp))
        buf += oversized_rp
        buf += struct.pack('!H', 25)  # script_len
        buf += b'\x00' * 25
        buf += struct.pack('!B', 0)  # token_data

        with pytest.raises(ValueError, match='range proof size.*exceeds maximum'):
            deserialize_shielded_output(buf)

    def test_valid_range_proof_size_accepted(self) -> None:
        """Range proof at MAX_RANGE_PROOF_SIZE should be accepted."""
        rp = b'\x00' * MAX_RANGE_PROOF_SIZE
        buf = struct.pack('!B', OutputMode.AMOUNT_ONLY)
        buf += b'\x02' + b'\x00' * 32
        buf += struct.pack('!H', len(rp))
        buf += rp
        buf += struct.pack('!H', 25)
        buf += b'\x00' * 25
        buf += struct.pack('!B', 0)
        buf += b'\x00' * 33  # ephemeral_pubkey (zeros = not present)
        # Should not raise
        output, remaining = deserialize_shielded_output(buf)
        assert isinstance(output, AmountShieldedOutput)

    def test_oversized_surjection_proof_rejected(self) -> None:
        """Surjection proof exceeding MAX_SURJECTION_PROOF_SIZE should be rejected."""
        oversized_sp = b'\x00' * (MAX_SURJECTION_PROOF_SIZE + 1)
        buf = struct.pack('!B', OutputMode.FULLY_SHIELDED)
        buf += b'\x02' + b'\x00' * 32  # commitment (33 bytes)
        buf += struct.pack('!H', 100)   # rp_len
        buf += b'\x00' * 100            # range_proof
        buf += struct.pack('!H', 25)    # script_len
        buf += b'\x00' * 25             # script
        buf += b'\x02' + b'\x00' * 32   # asset_commitment (33 bytes)
        buf += struct.pack('!H', len(oversized_sp))
        buf += oversized_sp

        with pytest.raises(ValueError, match='surjection proof size.*exceeds maximum'):
            deserialize_shielded_output(buf)


class TestIssue05_AuthorityOutputsBalance:
    """ISSUE-05: Authority outputs should not corrupt balance equation."""

    def test_authority_output_skipped_in_balance(self) -> None:
        """Authority outputs should be filtered from the transparent outputs in balance check."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        # Mock transparent input: 1000 HTR
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

        # Mock transparent output: 1000 HTR (regular)
        tx_output_regular = MagicMock()
        tx_output_regular.value = 1000
        tx_output_regular.get_token_index = MagicMock(return_value=0)
        tx_output_regular.is_token_authority = MagicMock(return_value=False)

        # Mock authority output (should be skipped)
        tx_output_authority = MagicMock()
        tx_output_authority.value = 0b10000001  # authority bitmask, not real amount
        tx_output_authority.get_token_index = MagicMock(return_value=0)
        tx_output_authority.is_token_authority = MagicMock(return_value=True)

        fee_header = MagicMock()
        fee_header.total_fee_amount = MagicMock(return_value=0)

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = [tx_output_regular, tx_output_authority]
        tx.shielded_outputs = []
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=True)
        tx.get_fee_header = MagicMock(return_value=fee_header)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        # Should pass: 1000 in = 1000 out (authority output skipped)
        verifier.verify_shielded_balance(tx)

    def test_authority_input_skipped_in_balance(self) -> None:
        """Authority inputs should be filtered from the transparent inputs in balance check."""
        verifier = _make_verifier()
        token_uid = bytes(32)

        # Mock authority input (should be skipped)
        spent_tx_auth = MagicMock()
        spent_output_auth = MagicMock()
        spent_output_auth.value = 0b10000001
        spent_output_auth.get_token_index = MagicMock(return_value=0)
        spent_output_auth.is_token_authority = MagicMock(return_value=True)
        spent_tx_auth.outputs = [spent_output_auth]
        spent_tx_auth.shielded_outputs = []
        spent_tx_auth.get_token_uid = MagicMock(return_value=token_uid)

        tx_input_auth = MagicMock()
        tx_input_auth.tx_id = b'\x01' * 32
        tx_input_auth.index = 0

        # Mock regular input
        spent_tx_reg = MagicMock()
        spent_output_reg = MagicMock()
        spent_output_reg.value = 500
        spent_output_reg.get_token_index = MagicMock(return_value=0)
        spent_output_reg.is_token_authority = MagicMock(return_value=False)
        spent_tx_reg.outputs = [spent_output_reg]
        spent_tx_reg.shielded_outputs = []
        spent_tx_reg.get_token_uid = MagicMock(return_value=token_uid)

        tx_input_reg = MagicMock()
        tx_input_reg.tx_id = b'\x02' * 32
        tx_input_reg.index = 0

        # Mock output
        tx_output = MagicMock()
        tx_output.value = 500
        tx_output.get_token_index = MagicMock(return_value=0)
        tx_output.is_token_authority = MagicMock(return_value=False)

        fee_header = MagicMock()
        fee_header.total_fee_amount = MagicMock(return_value=0)

        tx = MagicMock()
        tx.inputs = [tx_input_auth, tx_input_reg]
        tx.outputs = [tx_output]
        tx.shielded_outputs = []
        tx.get_token_uid = MagicMock(return_value=token_uid)
        tx.has_fees = MagicMock(return_value=True)
        tx.get_fee_header = MagicMock(return_value=fee_header)
        tx.storage = MagicMock()

        def get_spent_tx(tx_id: bytes) -> MagicMock:
            if tx_id == b'\x01' * 32:
                return spent_tx_auth
            return spent_tx_reg

        tx.storage.get_transaction = MagicMock(side_effect=get_spent_tx)

        # Should pass: 500 in = 500 out (authority input skipped)
        verifier.verify_shielded_balance(tx)


class TestIssue06_TokenDataBoundsCheck:
    """ISSUE-06: Out-of-bounds token_data index should raise, not crash."""

    def test_token_data_out_of_bounds(self) -> None:
        """token_data referencing non-existent token should raise InvalidShieldedOutputError."""
        verifier = _make_verifier()
        output = AmountShieldedOutput(
            commitment=b'\x02' + b'\x00' * 32,
            range_proof=b'\x00' * 100,
            script=b'\x00' * 25,
            token_data=5,  # index 5, but only 0 tokens in list
        )
        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.tokens = []  # empty token list
        tx.get_token_uid = MagicMock(side_effect=IndexError('list index out of range'))

        with pytest.raises(InvalidShieldedOutputError, match='token_data index'):
            verifier.verify_range_proofs(tx)

    def test_token_data_zero_always_valid(self) -> None:
        """token_data=0 (HTR) should always be valid regardless of token list."""
        verifier = _make_verifier()
        output = _make_amount_shielded(amount=100, token_data=0)
        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.tokens = []
        tx.get_token_uid = MagicMock(return_value=b'\x00')
        # Should not raise on bounds check (may pass or fail on range proof)
        verifier.verify_range_proofs(tx)


class TestIssue02_InvalidShieldedInputReferences:
    """ISSUE-02: Invalid shielded input references should raise, not silently skip."""

    def test_surjection_invalid_shielded_index_raises(self) -> None:
        """Input referencing non-existent shielded output should raise."""
        verifier = _make_verifier()
        output = _make_full_shielded()

        # Spent tx has 1 regular output, no shielded outputs
        spent_tx = MagicMock()
        spent_tx.outputs = [MagicMock()]
        spent_tx.shielded_outputs = []

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 5  # index 5 > len(outputs)=1, shielded_index=4 > len(shielded)=0

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.outputs = []
        tx.inputs = [tx_input]
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(InvalidShieldedOutputError, match='non-existent shielded output'):
            verifier.verify_surjection_proofs(tx)

    def test_balance_invalid_shielded_index_raises(self) -> None:
        """Balance check: input referencing non-existent shielded output should raise."""
        verifier = _make_verifier()

        spent_tx = MagicMock()
        spent_tx.outputs = [MagicMock()]
        spent_tx.shielded_outputs = []

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 3  # beyond regular + shielded

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = []
        tx.shielded_outputs = []
        tx.has_fees = MagicMock(return_value=False)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(InvalidShieldedOutputError, match='non-existent shielded output'):
            verifier.verify_shielded_balance(tx)

    def test_balance_no_shielded_outputs_raises(self) -> None:
        """Balance check: spent tx with empty shielded_outputs should raise."""
        verifier = _make_verifier()

        spent_tx = MagicMock()
        spent_tx.outputs = [MagicMock()]
        spent_tx.shielded_outputs = []

        tx_input = MagicMock()
        tx_input.tx_id = b'\x00' * 32
        tx_input.index = 2

        tx = MagicMock()
        tx.inputs = [tx_input]
        tx.outputs = []
        tx.shielded_outputs = []
        tx.has_fees = MagicMock(return_value=False)
        tx.storage = MagicMock()
        tx.storage.get_transaction = MagicMock(return_value=spent_tx)

        with pytest.raises(InvalidShieldedOutputError, match='non-existent shielded output'):
            verifier.verify_shielded_balance(tx)


class TestIssue14_EmptySurjectionDomain:
    """ISSUE-14: Empty surjection proof domain should be rejected."""

    def test_full_shielded_no_inputs_raises(self) -> None:
        """FullShieldedOutput with no inputs (empty domain) should raise."""
        verifier = _make_verifier()
        output = _make_full_shielded()

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.outputs = []
        tx.inputs = []  # No inputs → empty domain
        tx.storage = MagicMock()

        with pytest.raises(InvalidSurjectionProofError, match='at least one input'):
            verifier.verify_surjection_proofs(tx)

    def test_amount_shielded_no_inputs_ok(self) -> None:
        """AmountShieldedOutput with no inputs should NOT trigger surjection domain check."""
        verifier = _make_verifier()
        output = _make_amount_shielded()

        tx = MagicMock()
        tx.shielded_outputs = [output]
        tx.outputs = []
        tx.inputs = []
        tx.storage = MagicMock()

        # Should not raise — AmountShieldedOutput doesn't need surjection
        verifier.verify_surjection_proofs(tx)


class TestIssue15_TokenUidValidation:
    """ISSUE-15: Token UID normalization should reject invalid lengths."""

    def test_valid_1_byte_uid(self) -> None:
        from hathor.verification.shielded_transaction_verifier import _normalize_token_uid
        result = _normalize_token_uid(b'\x00')
        assert len(result) == 32
        assert result == bytes(32)

    def test_valid_32_byte_uid(self) -> None:
        from hathor.verification.shielded_transaction_verifier import _normalize_token_uid
        uid = os.urandom(32)
        result = _normalize_token_uid(uid)
        assert result == uid

    def test_invalid_length_rejected(self) -> None:
        from hathor.verification.shielded_transaction_verifier import _normalize_token_uid
        with pytest.raises(InvalidShieldedOutputError, match='invalid token UID length'):
            _normalize_token_uid(b'\x00\x01')  # 2 bytes

    def test_16_byte_uid_rejected(self) -> None:
        from hathor.verification.shielded_transaction_verifier import _normalize_token_uid
        with pytest.raises(InvalidShieldedOutputError, match='invalid token UID length'):
            _normalize_token_uid(os.urandom(16))


class TestIssue16_HeaderDeserializationTypeCheck:
    """ISSUE-16: Header deserialization should reject non-Transaction types."""

    def test_non_transaction_rejected(self) -> None:
        """Passing a non-Transaction (e.g., Block) to ShieldedOutputsHeader.deserialize should raise."""
        from hathor.transaction import Block
        block = MagicMock(spec=Block)

        # Minimal valid header bytes
        from hathor.transaction.headers.types import VertexHeaderId
        buf = VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value + b'\x01'

        with pytest.raises(InvalidShieldedOutputError, match='requires a Transaction'):
            ShieldedOutputsHeader.deserialize(block, buf)

    def test_malformed_header_caught(self) -> None:
        """Truncated header data should raise InvalidShieldedOutputError, not raw exception."""
        from hathor.transaction.transaction import Transaction
        tx = MagicMock(spec=Transaction)

        from hathor.transaction.headers.types import VertexHeaderId

        # Truncated: header_id + num_outputs=1 but no actual output data
        buf = VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value + b'\x01'

        with pytest.raises(InvalidShieldedOutputError, match='malformed'):
            ShieldedOutputsHeader.deserialize(tx, buf)


class TestIssue03_HeaderNumOutputsLimits:
    """ISSUE-03: num_outputs=0 and num_outputs > MAX should be rejected at deserialization."""

    def test_zero_outputs_rejected(self) -> None:
        from hathor.transaction.headers.types import VertexHeaderId
        from hathor.transaction.transaction import Transaction

        tx = MagicMock(spec=Transaction)
        buf = VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value + b'\x00'

        with pytest.raises(InvalidShieldedOutputError, match='at least 1 output'):
            ShieldedOutputsHeader.deserialize(tx, buf)

    def test_excess_outputs_rejected(self) -> None:
        from hathor.transaction.headers.types import VertexHeaderId
        from hathor.transaction.transaction import Transaction

        tx = MagicMock(spec=Transaction)
        num = MAX_SHIELDED_OUTPUTS + 1
        buf = VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value + bytes([num])

        with pytest.raises(InvalidShieldedOutputError, match='too many shielded outputs'):
            ShieldedOutputsHeader.deserialize(tx, buf)
