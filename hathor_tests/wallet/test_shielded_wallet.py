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

"""Tests for wallet recovery of shielded output amounts and tokens."""

import os

import hathor_ct_crypto as lib

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.crypto.shielded import create_range_proof, derive_asset_tag
from hathor.crypto.shielded.ecdh import (
    derive_ecdh_shared_secret,
    derive_rewind_nonce,
    extract_key_bytes,
    generate_ephemeral_keypair,
)
from hathor.transaction.scripts import P2PKH
from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput


def _create_amount_shielded_output_for_wallet(
    amount: int,
    recipient_pubkey: bytes,
    script: bytes,
    token_data: int = 0,
) -> tuple[AmountShieldedOutput, bytes]:
    """Create an AmountShieldedOutput with ECDH-based rewindable proof.

    Returns (output, token_uid_32B)
    """
    token_uid = HATHOR_TOKEN_UID.ljust(32, b'\x00')
    gen = derive_asset_tag(token_uid)
    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, gen)

    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    shared_secret = derive_ecdh_shared_secret(ephemeral_priv, recipient_pubkey)
    nonce = derive_rewind_nonce(shared_secret)

    range_proof = create_range_proof(amount, blinding, commitment, gen, nonce=nonce)

    output = AmountShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        token_data=token_data,
        ephemeral_pubkey=ephemeral_pub,
    )
    return output, token_uid


def _create_full_shielded_output_for_wallet(
    amount: int,
    recipient_pubkey: bytes,
    script: bytes,
    token_uid: bytes | None = None,
) -> tuple[FullShieldedOutput, bytes]:
    """Create a FullShieldedOutput with ECDH-based rewindable proof.

    Returns (output, token_uid_32B)
    """
    if token_uid is None:
        token_uid = HATHOR_TOKEN_UID.ljust(32, b'\x00')

    raw_tag = lib.derive_tag(token_uid)
    asset_blinding = os.urandom(32)
    asset_comm = lib.create_asset_commitment(raw_tag, asset_blinding)

    blinding = os.urandom(32)
    commitment = lib.create_commitment(amount, blinding, asset_comm)

    ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
    shared_secret = derive_ecdh_shared_secret(ephemeral_priv, recipient_pubkey)
    nonce = derive_rewind_nonce(shared_secret)

    message = token_uid + asset_blinding
    range_proof = create_range_proof(amount, blinding, commitment, asset_comm, message=message, nonce=nonce)

    # Create trivial surjection proof
    input_gen = lib.derive_asset_tag(token_uid)
    surjection_proof = lib.create_surjection_proof(raw_tag, asset_blinding, [(input_gen, raw_tag, bytes(32))])

    output = FullShieldedOutput(
        commitment=commitment,
        range_proof=range_proof,
        script=script,
        asset_commitment=asset_comm,
        surjection_proof=surjection_proof,
        ephemeral_pubkey=ephemeral_pub,
    )
    return output, token_uid


def _make_mock_wallet_and_tx(
    shielded_outputs: list,
    address: str,
    private_key: object,
) -> tuple:
    """Create a mock wallet and mock transaction for testing shielded output recovery.

    Returns (wallet, tx)
    """
    from collections import defaultdict
    from unittest.mock import MagicMock

    from hathor.wallet.base_wallet import BaseWallet

    wallet = MagicMock(spec=BaseWallet)
    wallet.keys = {address: True}
    wallet.unspent_txs = defaultdict(dict)
    wallet.maybe_spent_txs = defaultdict(dict)
    wallet.log = MagicMock()
    wallet.get_private_key = MagicMock(return_value=private_key)
    wallet.tokens_received = MagicMock()
    wallet.publish_update = MagicMock()
    wallet.get_total_tx = MagicMock(return_value=1)

    # Bind the real method to the mock
    import types
    wallet._process_shielded_outputs_on_new_tx = types.MethodType(
        BaseWallet._process_shielded_outputs_on_new_tx, wallet
    )

    tx = MagicMock()
    tx.hash = os.urandom(32)
    tx.hash_hex = tx.hash.hex()
    tx.timestamp = 1000
    tx.outputs = []
    tx.shielded_outputs = shielded_outputs
    tx.get_token_uid = MagicMock(side_effect=lambda idx: HATHOR_TOKEN_UID if idx == 0 else os.urandom(32))

    return wallet, tx


class TestWalletShieldedOutputRecovery:
    def test_wallet_receives_amount_shielded_output(self) -> None:
        """Wallet should recover the amount from an AmountShieldedOutput."""
        from cryptography.hazmat.primitives.asymmetric import ec

        from hathor.crypto.util import decode_address, get_address_b58_from_public_key

        # Create a wallet key
        private_key = ec.generate_private_key(ec.SECP256K1())
        _, pubkey_bytes = extract_key_bytes(private_key)
        address = get_address_b58_from_public_key(private_key.public_key())
        address_bytes = decode_address(address)

        script = P2PKH.create_output_script(address_bytes)
        amount = 1234

        output, token_uid = _create_amount_shielded_output_for_wallet(
            amount, pubkey_bytes, script
        )

        wallet, tx = _make_mock_wallet_and_tx([output], address, private_key)

        result = wallet._process_shielded_outputs_on_new_tx(tx)
        assert result is True

        # Check that UTXO was added
        token_id = HATHOR_TOKEN_UID
        actual_index = 0  # len(tx.outputs) = 0, shielded_idx = 0
        utxo = wallet.unspent_txs[token_id].get((tx.hash, actual_index))
        assert utxo is not None
        assert utxo.value == amount
        assert utxo.address == address

    def test_wallet_receives_full_shielded_output(self) -> None:
        """Wallet should recover amount and token from a FullShieldedOutput."""
        from cryptography.hazmat.primitives.asymmetric import ec

        from hathor.crypto.util import decode_address, get_address_b58_from_public_key

        private_key = ec.generate_private_key(ec.SECP256K1())
        _, pubkey_bytes = extract_key_bytes(private_key)
        address = get_address_b58_from_public_key(private_key.public_key())
        address_bytes = decode_address(address)

        script = P2PKH.create_output_script(address_bytes)
        amount = 5678
        token_uid = os.urandom(32)

        output, _ = _create_full_shielded_output_for_wallet(
            amount, pubkey_bytes, script, token_uid=token_uid
        )

        wallet, tx = _make_mock_wallet_and_tx([output], address, private_key)

        result = wallet._process_shielded_outputs_on_new_tx(tx)
        assert result is True

        # For FullShielded, token_id comes from message (first 32 bytes)
        actual_index = 0
        utxo = wallet.unspent_txs[token_uid].get((tx.hash, actual_index))
        assert utxo is not None
        assert utxo.value == amount
        assert utxo.address == address

    def test_wallet_ignores_other_address(self) -> None:
        """Output for different wallet should be skipped."""
        from cryptography.hazmat.primitives.asymmetric import ec

        from hathor.crypto.util import decode_address, get_address_b58_from_public_key

        # Recipient's key
        recipient_key = ec.generate_private_key(ec.SECP256K1())
        _, recipient_pubkey = extract_key_bytes(recipient_key)
        recipient_address = get_address_b58_from_public_key(recipient_key.public_key())
        recipient_address_bytes = decode_address(recipient_address)
        script = P2PKH.create_output_script(recipient_address_bytes)

        # Different wallet key (not the recipient)
        other_key = ec.generate_private_key(ec.SECP256K1())
        other_address = get_address_b58_from_public_key(other_key.public_key())

        output, _ = _create_amount_shielded_output_for_wallet(100, recipient_pubkey, script)

        wallet, tx = _make_mock_wallet_and_tx([output], other_address, other_key)

        result = wallet._process_shielded_outputs_on_new_tx(tx)
        assert result is False

        # No UTXOs should have been added
        for token_utxos in wallet.unspent_txs.values():
            assert len(token_utxos) == 0

    def test_wallet_skips_output_without_ephemeral_pubkey(self) -> None:
        """Outputs without ephemeral pubkey should be skipped."""
        from cryptography.hazmat.primitives.asymmetric import ec

        from hathor.crypto.util import decode_address, get_address_b58_from_public_key

        private_key = ec.generate_private_key(ec.SECP256K1())
        address = get_address_b58_from_public_key(private_key.public_key())
        address_bytes = decode_address(address)
        script = P2PKH.create_output_script(address_bytes)

        gen = derive_asset_tag(HATHOR_TOKEN_UID.ljust(32, b'\x00'))
        blinding = os.urandom(32)
        commitment = lib.create_commitment(100, blinding, gen)
        range_proof = create_range_proof(100, blinding, commitment, gen)

        # No ephemeral pubkey (legacy output)
        output = AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=0,
        )

        wallet, tx = _make_mock_wallet_and_tx([output], address, private_key)

        result = wallet._process_shielded_outputs_on_new_tx(tx)
        assert result is False
