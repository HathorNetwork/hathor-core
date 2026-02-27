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

"""Tests for ECDH key exchange and nonce derivation for shielded output recovery."""

import os

import hathor_ct_crypto as lib
import pytest

from hathor.crypto.shielded.ecdh import (
    derive_ecdh_shared_secret,
    derive_rewind_nonce,
    extract_key_bytes,
    generate_ephemeral_keypair,
)
from hathor.crypto.shielded.range_proof import create_range_proof, rewind_range_proof


class TestECDH:
    def test_generate_ephemeral_keypair(self) -> None:
        privkey, pubkey = generate_ephemeral_keypair()
        assert len(privkey) == 32
        assert len(pubkey) == 33
        # Compressed pubkey starts with 0x02 or 0x03
        assert pubkey[0] in (0x02, 0x03)

    def test_ecdh_symmetric(self) -> None:
        """A's privkey + B's pubkey == B's privkey + A's pubkey."""
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()

        secret_ab = derive_ecdh_shared_secret(priv_a, pub_b)
        secret_ba = derive_ecdh_shared_secret(priv_b, pub_a)

        assert secret_ab == secret_ba
        assert len(secret_ab) == 32

    def test_different_keys_different_secrets(self) -> None:
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()

        secret_ab = derive_ecdh_shared_secret(priv_a, pub_b)
        secret_ac = derive_ecdh_shared_secret(priv_a, pub_c)
        assert secret_ab != secret_ac

    def test_nonce_deterministic(self) -> None:
        """Same input -> same nonce."""
        shared_secret = os.urandom(32)
        nonce1 = derive_rewind_nonce(shared_secret)
        nonce2 = derive_rewind_nonce(shared_secret)
        assert nonce1 == nonce2
        assert len(nonce1) == 32

    def test_different_secrets_different_nonces(self) -> None:
        nonce1 = derive_rewind_nonce(os.urandom(32))
        nonce2 = derive_rewind_nonce(os.urandom(32))
        assert nonce1 != nonce2


class TestExtractKeyBytes:
    def test_cryptography_key(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        private_key = ec.generate_private_key(ec.SECP256K1())
        privkey_bytes, pubkey_bytes = extract_key_bytes(private_key)
        assert len(privkey_bytes) == 32
        assert len(pubkey_bytes) == 33
        assert pubkey_bytes[0] in (0x02, 0x03)

    def test_unsupported_type(self) -> None:
        with pytest.raises(TypeError, match='unsupported key type'):
            extract_key_bytes("not a key")


class TestFullECDHRewindRoundtrip:
    def test_full_ecdh_rewind_roundtrip(self) -> None:
        """Generate ephemeral key -> ECDH -> create proof with nonce -> rewind recovers value."""
        # Recipient's key pair
        recipient_priv, recipient_pub = generate_ephemeral_keypair()

        # Sender generates ephemeral key and computes shared secret
        sender_priv, sender_pub = generate_ephemeral_keypair()
        sender_shared = derive_ecdh_shared_secret(sender_priv, recipient_pub)
        nonce = derive_rewind_nonce(sender_shared)

        # Create commitment and range proof with deterministic nonce
        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 7777
        commitment = lib.create_commitment(amount, blinding, gen)
        proof = create_range_proof(amount, blinding, commitment, gen, nonce=nonce)

        # Recipient computes same shared secret
        recipient_shared = derive_ecdh_shared_secret(recipient_priv, sender_pub)
        assert recipient_shared == sender_shared

        recipient_nonce = derive_rewind_nonce(recipient_shared)
        assert recipient_nonce == nonce

        # Recipient rewinds the proof
        value, recovered_blinding, message = rewind_range_proof(proof, commitment, recipient_nonce, gen)
        assert value == amount
        assert recovered_blinding == blinding

    def test_full_shielded_ecdh_rewind_with_message(self) -> None:
        """FullShieldedOutput: recover token_uid and asset_blinding from message."""
        recipient_priv, recipient_pub = generate_ephemeral_keypair()
        sender_priv, sender_pub = generate_ephemeral_keypair()
        sender_shared = derive_ecdh_shared_secret(sender_priv, recipient_pub)
        nonce = derive_rewind_nonce(sender_shared)

        # For FullShielded, use blinded generator
        token_uid = os.urandom(32)
        raw_tag = lib.derive_tag(token_uid)
        asset_blinding = os.urandom(32)
        asset_comm = lib.create_asset_commitment(raw_tag, asset_blinding)

        blinding = os.urandom(32)
        amount = 5000
        commitment = lib.create_commitment(amount, blinding, asset_comm)

        # Embed token_uid + asset_blinding in message
        message = token_uid + asset_blinding
        proof = create_range_proof(amount, blinding, commitment, asset_comm, message=message, nonce=nonce)

        # Recipient rewinds
        recipient_shared = derive_ecdh_shared_secret(recipient_priv, sender_pub)
        recipient_nonce = derive_rewind_nonce(recipient_shared)
        value, recovered_blinding, recovered_message = rewind_range_proof(
            proof, commitment, recipient_nonce, asset_comm
        )

        assert value == amount
        assert recovered_blinding == blinding
        # First 32 bytes of message = token_uid, next 32 bytes = asset_blinding
        assert recovered_message[:32] == token_uid
        assert recovered_message[32:64] == asset_blinding

    def test_wrong_recipient_fails(self) -> None:
        """Rewind with wrong recipient's key should fail."""
        recipient_priv, recipient_pub = generate_ephemeral_keypair()
        wrong_priv, wrong_pub = generate_ephemeral_keypair()
        sender_priv, sender_pub = generate_ephemeral_keypair()

        sender_shared = derive_ecdh_shared_secret(sender_priv, recipient_pub)
        nonce = derive_rewind_nonce(sender_shared)

        gen = lib.htr_asset_tag()
        blinding = os.urandom(32)
        amount = 100
        commitment = lib.create_commitment(amount, blinding, gen)
        proof = create_range_proof(amount, blinding, commitment, gen, nonce=nonce)

        # Wrong recipient tries to rewind
        wrong_shared = derive_ecdh_shared_secret(wrong_priv, sender_pub)
        wrong_nonce = derive_rewind_nonce(wrong_shared)
        assert wrong_nonce != nonce

        with pytest.raises(ValueError):
            rewind_range_proof(proof, commitment, wrong_nonce, gen)
