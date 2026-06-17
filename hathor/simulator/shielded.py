#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Construct (and rewind) shielded outputs for the simulator.

On `master` the native CT crypto does not exist, so this module produces DUMMY
shielded outputs: correctly-sized placeholder bytes that the cryptographically
hollow verifier accepts when ENABLE_SHIELDED_TRANSACTIONS is on. Dummy outputs
are NOT rewindable.

The REAL, rewindable path mirrors the construction on the feat/shielded-outputs
branch and is selected automatically once the native `hathor.crypto.shielded`
module is importable and a recipient pubkey is supplied.
"""

from __future__ import annotations

import random

from hathorlib.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    ShieldedOutput,
    ShieldedOutputSecrets,
)

# Dummy proof sizes — within protocol maxima, plausible for a Bulletproof/surjection proof.
_DUMMY_RANGE_PROOF_SIZE = 675
_DUMMY_SURJECTION_PROOF_SIZE = 132

try:
    # Native CT crypto only exists on feat/shielded-outputs.
    from hathor.crypto.shielded import SHIELDED_CRYPTO_AVAILABLE
except ImportError:
    SHIELDED_CRYPTO_AVAILABLE = False


def build_shielded_output(
    *,
    amount: int,
    token_uid: bytes,
    token_data: int,
    script: bytes,
    mode: OutputMode,
    recipient_pubkey: bytes | None = None,
    rng: random.Random | None = None,
    force_dummy: bool = False,
) -> ShieldedOutput:
    """Build one shielded output.

    Returns a REAL rewindable output when the native crypto is available, a
    recipient_pubkey is given, and force_dummy is False; otherwise a DUMMY one.
    """
    if rng is None:
        rng = random.Random()
    if not force_dummy and SHIELDED_CRYPTO_AVAILABLE and recipient_pubkey is not None:
        return _build_real_shielded_output(
            amount=amount,
            token_uid=token_uid,
            token_data=token_data,
            script=script,
            mode=mode,
            recipient_pubkey=recipient_pubkey,
        )
    return _build_dummy_shielded_output(token_data=token_data, script=script, mode=mode, rng=rng)


def _dummy_ephemeral_pubkey(rng: random.Random) -> bytes:
    """33-byte compressed-pubkey-shaped bytes; non-zero so it decodes as 'present'."""
    return b'\x02' + rng.randbytes(EPHEMERAL_PUBKEY_SIZE - 1)


def _build_dummy_shielded_output(
    *,
    token_data: int,
    script: bytes,
    mode: OutputMode,
    rng: random.Random,
) -> ShieldedOutput:
    commitment = rng.randbytes(COMMITMENT_SIZE)
    range_proof = rng.randbytes(_DUMMY_RANGE_PROOF_SIZE)
    ephemeral_pubkey = _dummy_ephemeral_pubkey(rng)

    if mode == OutputMode.AMOUNT_ONLY:
        return AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    if mode == OutputMode.FULLY_SHIELDED:
        return FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=rng.randbytes(ASSET_COMMITMENT_SIZE),
            surjection_proof=rng.randbytes(_DUMMY_SURJECTION_PROOF_SIZE),
            ephemeral_pubkey=ephemeral_pubkey,
        )
    raise ValueError(f'unsupported shielded output mode: {mode!r}')


def _build_real_shielded_output(
    *,
    amount: int,
    token_uid: bytes,
    token_data: int,
    script: bytes,
    mode: OutputMode,
    recipient_pubkey: bytes,
) -> ShieldedOutput:
    """Real, rewindable shielded output (requires native CT crypto).

    Mirrors feat/shielded-outputs: per-token generator (derive_asset_tag),
    ephemeral ECDH keypair, rewind nonce, Pedersen commitment + Bulletproof
    range proof bound to that nonce so the recipient can rewind_range_proof().
    """
    import os

    from hathor.crypto.shielded import create_commitment, create_range_proof, derive_asset_tag
    from hathor.crypto.shielded.ecdh import (
        derive_ecdh_shared_secret,
        derive_rewind_nonce,
        generate_ephemeral_keypair,
    )

    generator = derive_asset_tag(token_uid)
    blinding = os.urandom(32)
    ephemeral_privkey, ephemeral_pubkey = generate_ephemeral_keypair()
    shared_secret = derive_ecdh_shared_secret(ephemeral_privkey, recipient_pubkey)
    nonce = derive_rewind_nonce(shared_secret)
    commitment = create_commitment(amount, blinding, generator)
    range_proof = create_range_proof(amount, blinding, commitment, generator, nonce=nonce)

    if mode == OutputMode.AMOUNT_ONLY:
        return AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    # FULLY_SHIELDED needs asset commitment + surjection proof; lands with the crypto merge.
    raise NotImplementedError('real FULLY_SHIELDED construction lands with the crypto merge')


def rewind_shielded_output(
    output: ShieldedOutput,
    privkey_bytes: bytes,
    token_uid: bytes,
) -> ShieldedOutputSecrets:
    """Recover (value, blinding, message) from a shielded output via ECDH rewind.

    Requires the native CT crypto. Raises RuntimeError when unavailable (master).
    This is the wallet-service balance path.
    """
    if not SHIELDED_CRYPTO_AVAILABLE:
        raise RuntimeError('native CT crypto not available; cannot rewind on this branch')

    from hathor.crypto.shielded import derive_asset_tag, rewind_range_proof
    from hathor.crypto.shielded.ecdh import derive_ecdh_shared_secret, derive_rewind_nonce

    assert output.ephemeral_pubkey is not None, 'output has no ephemeral pubkey; not rewindable'
    shared_secret = derive_ecdh_shared_secret(privkey_bytes, output.ephemeral_pubkey)
    nonce = derive_rewind_nonce(shared_secret)
    generator = derive_asset_tag(token_uid)
    value, blinding, message = rewind_range_proof(output.range_proof, output.commitment, nonce, generator)
    return ShieldedOutputSecrets(
        value=value,
        blinding_factor=blinding,
        message=message,
        token_uid=token_uid,
    )
