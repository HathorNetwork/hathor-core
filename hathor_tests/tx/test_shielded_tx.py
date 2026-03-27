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

"""Tests for shielded transaction output types and header serialization."""

import os

import hathor_ct_crypto as lib
import pytest

from hathor.transaction.shielded_tx_output import (
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    deserialize_shielded_output,
    get_sighash_bytes,
    serialize_shielded_output,
)


def _make_amount_shielded_output(amount: int = 1000, token_data: int = 0) -> AmountShieldedOutput:
    """Create a valid AmountShieldedOutput for testing."""
    gen = lib.htr_asset_tag()
    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, gen)
    range_proof = lib.create_range_proof(amount, blinding, commitment, gen)
    script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'  # P2PKH-like
    return AmountShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        token_data=token_data,
    )


def _make_full_shielded_output(amount: int = 500) -> FullShieldedOutput:
    """Create a valid FullShieldedOutput for testing."""
    token_uid = bytes(32)
    raw_tag = lib.derive_tag(token_uid)
    asset_bf = os.urandom(32)
    asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)

    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, asset_comm)
    range_proof = lib.create_range_proof(amount, blinding, commitment, asset_comm)

    # Create surjection proof with trivial domain
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


class TestOutputMode:
    def test_amount_only_mode(self) -> None:
        output = _make_amount_shielded_output()
        assert output.mode() == OutputMode.AMOUNT_ONLY
        assert output.mode() == 1

    def test_fully_shielded_mode(self) -> None:
        output = _make_full_shielded_output()
        assert output.mode() == OutputMode.FULLY_SHIELDED
        assert output.mode() == 2


class TestAmountShieldedOutput:
    def test_fields(self) -> None:
        output = _make_amount_shielded_output(amount=42, token_data=1)
        assert len(output.commitment) == 33
        assert len(output.range_proof) > 0
        assert len(output.script) > 0
        assert output.token_data == 1

    def test_frozen(self) -> None:
        output = _make_amount_shielded_output()
        with pytest.raises(AttributeError):
            output.commitment = b'\x00' * 33  # type: ignore[misc]

    def test_isinstance(self) -> None:
        output = _make_amount_shielded_output()
        assert isinstance(output, AmountShieldedOutput)
        assert not isinstance(output, FullShieldedOutput)


class TestFullShieldedOutput:
    def test_fields(self) -> None:
        output = _make_full_shielded_output()
        assert len(output.commitment) == 33
        assert len(output.range_proof) > 0
        assert len(output.script) > 0
        assert len(output.asset_commitment) == 33
        assert len(output.surjection_proof) > 0

    def test_frozen(self) -> None:
        output = _make_full_shielded_output()
        with pytest.raises(AttributeError):
            output.commitment = b'\x00' * 33  # type: ignore[misc]

    def test_isinstance(self) -> None:
        output = _make_full_shielded_output()
        assert isinstance(output, FullShieldedOutput)
        assert not isinstance(output, AmountShieldedOutput)


class TestSerialization:
    def test_amount_shielded_roundtrip(self) -> None:
        output = _make_amount_shielded_output(amount=42, token_data=2)
        data = serialize_shielded_output(output)
        restored, remaining = deserialize_shielded_output(data)
        assert remaining == b''
        assert isinstance(restored, AmountShieldedOutput)
        assert restored.commitment == output.commitment
        assert restored.range_proof == output.range_proof
        assert restored.script == output.script
        assert restored.token_data == output.token_data

    def test_full_shielded_roundtrip(self) -> None:
        output = _make_full_shielded_output()
        data = serialize_shielded_output(output)
        restored, remaining = deserialize_shielded_output(data)
        assert remaining == b''
        assert isinstance(restored, FullShieldedOutput)
        assert restored.commitment == output.commitment
        assert restored.range_proof == output.range_proof
        assert restored.script == output.script
        assert restored.asset_commitment == output.asset_commitment
        assert restored.surjection_proof == output.surjection_proof

    def test_multiple_outputs_concatenated(self) -> None:
        o1 = _make_amount_shielded_output(amount=100)
        o2 = _make_full_shielded_output(amount=200)
        data = serialize_shielded_output(o1) + serialize_shielded_output(o2)
        r1, remaining = deserialize_shielded_output(data)
        r2, remaining = deserialize_shielded_output(remaining)
        assert remaining == b''
        assert isinstance(r1, AmountShieldedOutput)
        assert isinstance(r2, FullShieldedOutput)


class TestSighashBytes:
    def test_amount_shielded_sighash_no_proofs(self) -> None:
        output = _make_amount_shielded_output()
        sighash = get_sighash_bytes(output)
        # Should NOT contain range_proof
        assert output.range_proof not in sighash
        # Should contain commitment and script
        assert output.commitment in sighash
        assert output.script in sighash

    def test_full_shielded_sighash_no_proofs(self) -> None:
        output = _make_full_shielded_output()
        sighash = get_sighash_bytes(output)
        # Should NOT contain range_proof or surjection_proof
        assert output.range_proof not in sighash
        assert output.surjection_proof not in sighash
        # Should contain commitment, asset_commitment, and script
        assert output.commitment in sighash
        assert output.asset_commitment in sighash
        assert output.script in sighash

    def test_different_modes_different_sighash(self) -> None:
        o1 = _make_amount_shielded_output()
        o2 = _make_full_shielded_output()
        s1 = get_sighash_bytes(o1)
        s2 = get_sighash_bytes(o2)
        # Mode byte differs so sighash must differ
        assert s1[0:1] != s2[0:1]


class TestEphemeralPubkeySerialization:
    def _make_ephemeral_pubkey(self) -> bytes:
        """Generate a valid compressed secp256k1 pubkey."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = ec.generate_private_key(ec.SECP256K1())
        return key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    def test_amount_shielded_with_ephemeral_pubkey_roundtrip(self) -> None:
        ephemeral = self._make_ephemeral_pubkey()
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        commitment = lib.create_commitment(1000, blinding, gen)
        range_proof = lib.create_range_proof(1000, blinding, commitment, gen)
        script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'

        output = AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=0,
            ephemeral_pubkey=ephemeral,
        )

        data = serialize_shielded_output(output)
        restored, remaining = deserialize_shielded_output(data)
        assert remaining == b''
        assert isinstance(restored, AmountShieldedOutput)
        assert restored.ephemeral_pubkey == ephemeral
        assert restored.commitment == output.commitment
        assert restored.token_data == output.token_data

    def test_full_shielded_with_ephemeral_pubkey_roundtrip(self) -> None:
        ephemeral = self._make_ephemeral_pubkey()
        token_uid = bytes(32)
        raw_tag = lib.derive_tag(token_uid)
        asset_bf = os.urandom(32)
        asset_comm = lib.create_asset_commitment(raw_tag, asset_bf)

        blinding = os.urandom(32)
        commitment = lib.create_commitment(500, blinding, asset_comm)
        range_proof = lib.create_range_proof(500, blinding, commitment, asset_comm)

        input_gen = lib.derive_asset_tag(token_uid)
        surjection_proof = lib.create_surjection_proof(
            raw_tag, asset_bf, [(input_gen, raw_tag, bytes(32))]
        )
        script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'

        output = FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=asset_comm,
            surjection_proof=surjection_proof,
            ephemeral_pubkey=ephemeral,
        )

        data = serialize_shielded_output(output)
        restored, remaining = deserialize_shielded_output(data)
        assert remaining == b''
        assert isinstance(restored, FullShieldedOutput)
        assert restored.ephemeral_pubkey == ephemeral
        assert restored.asset_commitment == output.asset_commitment

    def test_sighash_includes_ephemeral_pubkey(self) -> None:
        """Sighash with ephemeral pubkey differs from sighash without."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        commitment = lib.create_commitment(100, blinding, gen)
        range_proof = lib.create_range_proof(100, blinding, commitment, gen)
        script = b'\x76\xa9\x14' + os.urandom(20) + b'\x88\xac'

        without = AmountShieldedOutput(
            commitment=commitment, range_proof=range_proof, script=script, token_data=0,
        )
        ephemeral = self._make_ephemeral_pubkey()
        with_epk = AmountShieldedOutput(
            commitment=commitment, range_proof=range_proof, script=script, token_data=0,
            ephemeral_pubkey=ephemeral,
        )

        s1 = get_sighash_bytes(without)
        s2 = get_sighash_bytes(with_epk)
        assert s1 != s2
        # Both sighashes have the same length (ephemeral_pubkey is always
        # included — zero bytes when absent, actual pubkey when present)
        assert len(s2) == len(s1)

    def test_backward_compat_no_ephemeral_pubkey(self) -> None:
        """Legacy outputs without ephemeral pubkey still work."""
        output = _make_amount_shielded_output()
        assert output.ephemeral_pubkey == b''
        data = serialize_shielded_output(output)
        restored, remaining = deserialize_shielded_output(data)
        assert remaining == b''
        assert restored.ephemeral_pubkey == b''
