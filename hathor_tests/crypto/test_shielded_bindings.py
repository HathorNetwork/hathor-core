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

"""Tests for the hathor_ct_crypto Python bindings."""

import os

import hathor_ct_crypto as lib
import pytest


class TestConstants:
    def test_commitment_size(self) -> None:
        assert lib.COMMITMENT_SIZE == 33

    def test_generator_size(self) -> None:
        assert lib.GENERATOR_SIZE == 33

    def test_zero_tweak(self) -> None:
        assert isinstance(lib.ZERO_TWEAK, bytes)
        assert len(lib.ZERO_TWEAK) == 32
        assert lib.ZERO_TWEAK == bytes(32)


class TestGenerators:
    def test_htr_asset_tag(self) -> None:
        tag = lib.htr_asset_tag()
        assert isinstance(tag, bytes)
        assert len(tag) == 33

    def test_htr_asset_tag_deterministic(self) -> None:
        assert lib.htr_asset_tag() == lib.htr_asset_tag()

    def test_derive_asset_tag(self) -> None:
        token_uid = bytes(32)
        tag = lib.derive_asset_tag(token_uid)
        assert isinstance(tag, bytes)
        assert len(tag) == 33

    def test_derive_asset_tag_deterministic(self) -> None:
        token_uid = os.urandom(32)
        assert lib.derive_asset_tag(token_uid) == lib.derive_asset_tag(token_uid)

    def test_different_tokens_different_tags(self) -> None:
        tag1 = lib.derive_asset_tag(bytes(32))
        tag2 = lib.derive_asset_tag(b'\x01' + bytes(31))
        assert tag1 != tag2

    def test_derive_tag(self) -> None:
        raw_tag = lib.derive_tag(bytes(32))
        assert isinstance(raw_tag, bytes)
        assert len(raw_tag) == 32

    def test_create_asset_commitment(self) -> None:
        raw_tag = lib.derive_tag(bytes(32))
        r_asset = os.urandom(32)
        blinded = lib.create_asset_commitment(raw_tag, r_asset)
        assert isinstance(blinded, bytes)
        assert len(blinded) == 33

    def test_invalid_token_uid_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            lib.derive_asset_tag(b'\x00' * 16)


class TestPedersen:
    def test_create_commitment(self) -> None:
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        c = lib.create_commitment(1000, blinding, gen)
        assert isinstance(c, bytes)
        assert len(c) == 33

    def test_create_trivial_commitment(self) -> None:
        gen = lib.htr_asset_tag()
        c = lib.create_trivial_commitment(500, gen)
        assert isinstance(c, bytes)
        assert len(c) == 33

    def test_commitment_deterministic(self) -> None:
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        c1 = lib.create_commitment(100, blinding, gen)
        c2 = lib.create_commitment(100, blinding, gen)
        assert c1 == c2

    def test_hiding_property(self) -> None:
        gen = lib.htr_asset_tag()
        b1 = os.urandom(32)
        b2 = os.urandom(32)
        c1 = lib.create_commitment(100, b1, gen)
        c2 = lib.create_commitment(100, b2, gen)
        assert c1 != c2

    def test_verify_commitments_sum(self) -> None:
        gen = lib.htr_asset_tag()
        c1 = lib.create_trivial_commitment(300, gen)
        c2 = lib.create_trivial_commitment(700, gen)
        c_total = lib.create_trivial_commitment(1000, gen)
        assert lib.verify_commitments_sum([c1, c2], [c_total]) is True

    def test_verify_commitments_sum_mismatch(self) -> None:
        gen = lib.htr_asset_tag()
        c1 = lib.create_trivial_commitment(300, gen)
        c_wrong = lib.create_trivial_commitment(500, gen)
        assert lib.verify_commitments_sum([c1], [c_wrong]) is False


class TestRangeProof:
    def test_create_and_verify(self) -> None:
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 1000
        c = lib.create_commitment(amount, blinding, gen)
        proof = lib.create_range_proof(amount, blinding, c, gen)
        assert isinstance(proof, bytes)
        assert len(proof) > 0
        assert lib.verify_range_proof(proof, c, gen) is True

    def test_zero_amount_rejected(self) -> None:
        """Zero-amount range proofs must be rejected (min_value=1)."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        c = lib.create_commitment(0, blinding, gen)
        with pytest.raises(ValueError):
            lib.create_range_proof(0, blinding, c, gen)

    def test_wrong_commitment_fails(self) -> None:
        gen = lib.htr_asset_tag()
        b1 = os.urandom(32)
        b2 = os.urandom(32)
        c1 = lib.create_commitment(1000, b1, gen)
        c2 = lib.create_commitment(2000, b2, gen)
        proof = lib.create_range_proof(1000, b1, c1, gen)
        assert lib.verify_range_proof(proof, c2, gen) is False

    def test_with_message(self) -> None:
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        c = lib.create_commitment(42, blinding, gen)
        proof = lib.create_range_proof(42, blinding, c, gen, b"test message")
        assert lib.verify_range_proof(proof, c, gen) is True


class TestRewindRangeProof:
    def test_rewind_range_proof(self) -> None:
        """Full roundtrip through FFI: create with nonce -> rewind -> verify."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        nonce = os.urandom(32)
        amount = 12345
        c = lib.create_commitment(amount, blinding, gen)
        proof = lib.create_range_proof(amount, blinding, c, gen, nonce=nonce)
        assert lib.verify_range_proof(proof, c, gen) is True

        value, recovered_blinding, message = lib.rewind_range_proof(proof, c, nonce, gen)
        assert value == amount
        assert recovered_blinding == blinding

    def test_rewind_with_message(self) -> None:
        """Message recovery through rewind."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        nonce = os.urandom(32)
        amount = 500
        msg = b'token_uid_32bytes_______________' + b'asset_blinding_32bytes__________'
        c = lib.create_commitment(amount, blinding, gen)
        proof = lib.create_range_proof(amount, blinding, c, gen, message=msg, nonce=nonce)

        value, recovered_blinding, message = lib.rewind_range_proof(proof, c, nonce, gen)
        assert value == amount
        assert recovered_blinding == blinding
        # Message is padded to 4096 bytes; check prefix
        assert message[:len(msg)] == msg

    def test_rewind_wrong_nonce(self) -> None:
        """Wrong nonce should fail."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        nonce = os.urandom(32)
        wrong_nonce = os.urandom(32)
        amount = 100
        c = lib.create_commitment(amount, blinding, gen)
        proof = lib.create_range_proof(amount, blinding, c, gen, nonce=nonce)

        with pytest.raises(ValueError):
            lib.rewind_range_proof(proof, c, wrong_nonce, gen)

    def test_create_with_nonce_backward_compat(self) -> None:
        """Creating without nonce (None) should still work."""
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 42
        c = lib.create_commitment(amount, blinding, gen)
        proof = lib.create_range_proof(amount, blinding, c, gen)
        assert lib.verify_range_proof(proof, c, gen) is True


class TestSurjection:
    def test_create_and_verify(self) -> None:
        token_uid = bytes(32)
        raw_tag = lib.derive_tag(token_uid)
        input_bf = os.urandom(32)
        output_bf = os.urandom(32)
        input_gen = lib.create_asset_commitment(raw_tag, input_bf)
        output_gen = lib.create_asset_commitment(raw_tag, output_bf)
        proof = lib.create_surjection_proof(raw_tag, output_bf, [(input_gen, raw_tag, input_bf)])
        assert isinstance(proof, bytes)
        assert lib.verify_surjection_proof(proof, output_gen, [input_gen]) is True

    def test_wrong_output_fails(self) -> None:
        uid1 = bytes(32)
        uid2 = b'\x01' + bytes(31)
        raw_tag1 = lib.derive_tag(uid1)
        raw_tag2 = lib.derive_tag(uid2)
        input_bf = os.urandom(32)
        output_bf = os.urandom(32)
        input_gen = lib.create_asset_commitment(raw_tag1, input_bf)
        # Create a valid proof for token 1
        proof = lib.create_surjection_proof(raw_tag1, output_bf, [(input_gen, raw_tag1, input_bf)])
        output_gen = lib.create_asset_commitment(raw_tag1, output_bf)
        # Verify with wrong codomain generator (different token)
        wrong_gen = lib.create_asset_commitment(raw_tag2, output_bf)
        assert lib.verify_surjection_proof(proof, wrong_gen, [input_gen]) is False
        # Verify with correct codomain generator works
        assert lib.verify_surjection_proof(proof, output_gen, [input_gen]) is True

    def test_two_inputs(self) -> None:
        uid1 = bytes(32)
        uid2 = b'\x01' + bytes(31)
        raw_tag1 = lib.derive_tag(uid1)
        raw_tag2 = lib.derive_tag(uid2)
        bf1 = os.urandom(32)
        bf2 = os.urandom(32)
        output_bf = os.urandom(32)
        gen1 = lib.create_asset_commitment(raw_tag1, bf1)
        gen2 = lib.create_asset_commitment(raw_tag2, bf2)
        output_gen = lib.create_asset_commitment(raw_tag1, output_bf)
        proof = lib.create_surjection_proof(
            raw_tag1, output_bf,
            [(gen1, raw_tag1, bf1), (gen2, raw_tag2, bf2)]
        )
        assert lib.verify_surjection_proof(proof, output_gen, [gen1, gen2]) is True


class TestBalance:
    def test_transparent_balance(self) -> None:
        token_uid = bytes(32)
        ok = lib.verify_balance(
            [(1000, token_uid)], [], [(1000, token_uid)], []
        )
        assert ok is True

    def test_transparent_with_fee(self) -> None:
        token_uid = bytes(32)
        ok = lib.verify_balance(
            [(1000, token_uid)], [], [(900, token_uid), (100, token_uid)], []
        )
        assert ok is True

    def test_balance_mismatch(self) -> None:
        token_uid = bytes(32)
        ok = lib.verify_balance(
            [(1000, token_uid)], [], [(500, token_uid)], []
        )
        assert ok is False

    def test_compute_balancing_blinding_factor(self) -> None:
        result = lib.compute_balancing_blinding_factor(
            1000,
            bytes(32),  # generator blinding factor
            [(1000, os.urandom(32), bytes(32))],
            [],
        )
        assert isinstance(result, bytes)
        assert len(result) == 32

    # --- Excess blinding factor: full-unshield path ---

    def test_full_unshield_without_excess_is_rejected(self) -> None:
        """Full unshield (shielded in -> transparent out) without excess: rejected."""
        htr = bytes(32)
        gen = lib.htr_asset_tag()
        vbf_in = os.urandom(32)
        c_in = lib.create_commitment(1000, vbf_in, gen)

        ok = lib.verify_balance([], [c_in], [(1000, htr)], [])
        assert ok is False

    def test_full_unshield_with_correct_excess(self) -> None:
        """Full unshield with excess = sum(r_in) - sum(r_out) balances."""
        htr = bytes(32)
        gen = lib.htr_asset_tag()
        vbf_in = os.urandom(32)
        c_in = lib.create_commitment(1000, vbf_in, gen)

        excess = lib.compute_balancing_blinding_factor(
            0,
            bytes(32),
            [(1000, vbf_in, bytes(32))],
            [(1000, bytes(32), bytes(32))],
        )

        ok = lib.verify_balance([], [c_in], [(1000, htr)], [], excess)
        assert ok is True

    def test_full_unshield_with_wrong_excess_is_rejected(self) -> None:
        """An arbitrary scalar that isn't the actual excess doesn't balance."""
        htr = bytes(32)
        gen = lib.htr_asset_tag()
        vbf_in = os.urandom(32)
        c_in = lib.create_commitment(1000, vbf_in, gen)

        wrong_excess = os.urandom(32)
        ok = lib.verify_balance([], [c_in], [(1000, htr)], [], wrong_excess)
        assert ok is False

    def test_multi_token_full_unshield_with_excess(self) -> None:
        """HTR + custom token fully unshielded in one tx balances with excess."""
        htr = bytes(32)
        custom = b'\x07' * 32
        htr_gen = lib.htr_asset_tag()
        custom_gen = lib.derive_asset_tag(custom)

        vbf_htr = os.urandom(32)
        vbf_custom = os.urandom(32)
        c_htr = lib.create_commitment(500, vbf_htr, htr_gen)
        c_custom = lib.create_commitment(300, vbf_custom, custom_gen)

        excess = lib.compute_balancing_blinding_factor(
            0,
            bytes(32),
            [(500, vbf_htr, bytes(32)), (300, vbf_custom, bytes(32))],
            [(500, bytes(32), bytes(32)), (300, bytes(32), bytes(32))],
        )

        ok = lib.verify_balance(
            [], [c_htr, c_custom], [(500, htr), (300, custom)], [], excess
        )
        assert ok is True

    def test_excess_with_shielded_outputs_is_rejected_at_ffi(self) -> None:
        """Mutual-exclusivity invariant enforced at the Rust FFI boundary."""
        htr = bytes(32)
        gen = lib.htr_asset_tag()
        vbf = os.urandom(32)
        c_in = lib.create_commitment(1000, vbf, gen)
        c_out = lib.create_commitment(1000, vbf, gen)
        excess = os.urandom(32)

        with pytest.raises(ValueError, match='excess_blinding_factor must be None'):
            lib.verify_balance([], [c_in], [(1000, htr)], [c_out], excess)

    def test_excess_without_shielded_inputs_is_rejected_at_ffi(self) -> None:
        """Structural invariant: excess requires at least one shielded input."""
        htr = bytes(32)
        excess = os.urandom(32)
        with pytest.raises(ValueError, match='requires at least one shielded input'):
            lib.verify_balance([(1000, htr)], [], [(1000, htr)], [], excess)


class TestVerifyBalanceWrapper:
    """Tests for the Python wrapper at hathor/crypto/shielded/balance.py.

    The wrapper adds input validation on top of the raw FFI call:
      (a) mutual-exclusivity between excess_blinding_factor and shielded_outputs,
      (b) a 32-byte length check on the excess scalar.
    """

    def _htr_commitment(self, amount: int) -> tuple[bytes, bytes]:
        """Build a shielded HTR commitment and return (commitment, blinding_factor)."""
        gen = lib.htr_asset_tag()
        vbf = os.urandom(32)
        return lib.create_commitment(amount, vbf, gen), vbf

    def test_wrapper_full_unshield_happy_path(self) -> None:
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        c_in, vbf_in = self._htr_commitment(1000)
        excess = lib.compute_balancing_blinding_factor(
            0,
            bytes(32),
            [(1000, vbf_in, bytes(32))],
            [(1000, bytes(32), bytes(32))],
        )
        assert verify_balance([], [c_in], [(1000, htr)], [], excess) is True

    def test_wrapper_none_excess_passes_through(self) -> None:
        """No excess -> wrapper forwards as None; balanced tx still accepted."""
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        assert verify_balance([(1000, htr)], [], [(1000, htr)], []) is True

    def test_wrapper_rejects_excess_with_shielded_outputs(self) -> None:
        """Wrapper raises before even hitting the FFI when the invariant is violated."""
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        c_in, _ = self._htr_commitment(1000)
        c_out, _ = self._htr_commitment(1000)
        excess = os.urandom(32)

        with pytest.raises(ValueError, match='excess_blinding_factor must be None'):
            verify_balance([], [c_in], [(1000, htr)], [c_out], excess)

    def test_wrapper_rejects_wrong_sized_excess(self) -> None:
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        c_in, _ = self._htr_commitment(1000)

        with pytest.raises(ValueError, match='must be 32 bytes'):
            verify_balance([], [c_in], [(1000, htr)], [], b'\x01' * 16)
        with pytest.raises(ValueError, match='must be 32 bytes'):
            verify_balance([], [c_in], [(1000, htr)], [], b'\x01' * 33)

    def test_wrapper_rejects_excess_without_shielded_inputs(self) -> None:
        """Wrapper must reject excess when there are no shielded inputs to cancel."""
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        excess = os.urandom(32)
        with pytest.raises(ValueError, match='requires at least one shielded input'):
            verify_balance([(1000, htr)], [], [(1000, htr)], [], excess)

    def test_wrapper_full_unshield_without_excess_is_rejected(self) -> None:
        """Wrapper forwards None excess; FFI still rejects shielded-in -> transparent-out."""
        from hathor.crypto.shielded import verify_balance
        htr = bytes(32)
        c_in, _ = self._htr_commitment(1000)
        assert verify_balance([], [c_in], [(1000, htr)], []) is False
