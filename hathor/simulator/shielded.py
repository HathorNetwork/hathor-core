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

from hathor.util import Random
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

# On this branch the CT crypto is available via `hathorlib.crypto.shielded`, so the
# real construction path is used: the verifier validates commitments and range proofs
# for real, and dummy outputs would be rejected.
SHIELDED_CRYPTO_AVAILABLE = True


def build_shielded_output(
    *,
    amount: int,
    token_uid: bytes,
    token_data: int,
    script: bytes,
    mode: OutputMode,
    recipient_pubkey: bytes | None = None,
    value_blinding: bytes | None = None,
    asset_blinding: bytes | None = None,
    surjection_domain: list[tuple[bytes, bytes, bytes]] | None = None,
    rng: Random | None = None,
    force_dummy: bool = False,
) -> ShieldedOutput:
    """Build one shielded output.

    Returns a REAL rewindable output when the native crypto is available and
    force_dummy is False; otherwise a DUMMY one.

    `value_blinding` (and, for FULLY_SHIELDED, `asset_blinding`) let the caller
    pin the blinding factors so a set of outputs can be made to satisfy the
    homomorphic balance equation (see `compute_balancing_blinding_factor`); when
    omitted they are sampled at random.
    """
    if rng is None:
        rng = Random()
    # `recipient_pubkey` only governs rewindability (ECDH nonce); a valid, verifier-accepted
    # output can be built without it (nonce=None), so the real path runs whenever available.
    if not force_dummy and SHIELDED_CRYPTO_AVAILABLE:
        return _build_real_shielded_output(
            amount=amount,
            token_uid=token_uid,
            token_data=token_data,
            script=script,
            mode=mode,
            recipient_pubkey=recipient_pubkey,
            value_blinding=value_blinding,
            asset_blinding=asset_blinding,
            surjection_domain=surjection_domain,
        )
    return _build_dummy_shielded_output(token_data=token_data, script=script, mode=mode, rng=rng)


def _dummy_ephemeral_pubkey(rng: Random) -> bytes:
    """33-byte compressed-pubkey-shaped bytes; non-zero so it decodes as 'present'."""
    return b'\x02' + rng.randbytes(EPHEMERAL_PUBKEY_SIZE - 1)


def _build_dummy_shielded_output(
    *,
    token_data: int,
    script: bytes,
    mode: OutputMode,
    rng: Random,
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
    recipient_pubkey: bytes | None,
    value_blinding: bytes | None = None,
    asset_blinding: bytes | None = None,
    surjection_domain: list[tuple[bytes, bytes, bytes]] | None = None,
) -> ShieldedOutput:
    """Real, rewindable shielded output (uses `hathorlib.crypto.shielded`).

    Mirrors the `[shielded]`/`[full-shielded]` construction in
    `DAGBuilder`'s vertex exporter: per-token generator (`derive_asset_tag`),
    ephemeral ECDH keypair, rewind nonce, Pedersen commitment + Bulletproof
    range proof bound to that nonce so the recipient can `rewind_range_proof()`.
    When `recipient_pubkey` is None the output is still valid but not rewindable
    (no ECDH nonce, empty ephemeral pubkey).
    """
    import os

    from hathorlib.crypto.shielded import (
        create_asset_commitment,
        create_commitment,
        create_range_proof,
        create_surjection_proof,
        derive_asset_tag,
        derive_tag,
    )
    from hathorlib.crypto.shielded.ecdh import (
        derive_ecdh_shared_secret,
        derive_rewind_nonce,
        generate_ephemeral_keypair,
    )

    # Normalize token UID to 32 bytes for the crypto library.
    if len(token_uid) < 32:
        token_uid = token_uid.ljust(32, b'\x00')

    blinding = value_blinding if value_blinding is not None else os.urandom(32)
    ephemeral_privkey, ephemeral_pubkey = generate_ephemeral_keypair()
    if recipient_pubkey is not None:
        shared_secret = derive_ecdh_shared_secret(ephemeral_privkey, recipient_pubkey)
        nonce: bytes | None = derive_rewind_nonce(shared_secret)
    else:
        nonce = None
        ephemeral_pubkey = b''  # no ECDH possible without recipient pubkey

    if mode == OutputMode.FULLY_SHIELDED:
        # FullShieldedOutput: both amount and token hidden.
        raw_tag = derive_tag(token_uid)
        if asset_blinding is None:
            asset_blinding = os.urandom(32)
        asset_comm = create_asset_commitment(raw_tag, asset_blinding)
        commitment = create_commitment(amount, blinding, asset_comm)
        # Embed token_uid(32B) + asset_blinding(32B) in the range proof message.
        message = token_uid + asset_blinding
        range_proof = create_range_proof(
            amount, blinding, commitment, asset_comm, message=message, nonce=nonce,
        )
        # The surjection proof must be built over the SAME domain the verifier
        # reconstructs from the tx inputs (one unblinded asset tag per input, in
        # input order). The caller passes it in; absent that, fall back to a
        # trivial single-input domain of this output's own token.
        domain = surjection_domain if surjection_domain is not None \
            else [(derive_asset_tag(token_uid), raw_tag, bytes(32))]
        surjection_proof = create_surjection_proof(raw_tag, asset_blinding, domain)
        return FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=asset_comm,
            surjection_proof=surjection_proof,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    if mode == OutputMode.AMOUNT_ONLY:
        # AmountShieldedOutput: amount hidden, token visible.
        asset_tag = derive_asset_tag(token_uid)
        commitment = create_commitment(amount, blinding, asset_tag)
        range_proof = create_range_proof(amount, blinding, commitment, asset_tag, nonce=nonce)
        return AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    raise ValueError(f'unsupported shielded output mode: {mode!r}')


def rewind_shielded_output(
    output: ShieldedOutput,
    privkey_bytes: bytes,
    token_uid: bytes,
) -> ShieldedOutputSecrets:
    """Recover (value, blinding, message) from a shielded output via ECDH rewind.

    Requires the native CT crypto. Raises RuntimeError when unavailable (master).
    This is the wallet-service balance path.
    """
    # The native CT crypto (hathor.crypto.shielded) does not exist on this branch
    # yet, so rewinding is unavailable. When that package is integrated, restore the
    # `if not SHIELDED_CRYPTO_AVAILABLE` guard and uncomment the block below.
    raise RuntimeError('native CT crypto not available; cannot rewind on this branch')
    # from hathor.crypto.shielded import derive_asset_tag, rewind_range_proof
    # from hathor.crypto.shielded.ecdh import derive_ecdh_shared_secret, derive_rewind_nonce
    #
    # assert output.ephemeral_pubkey is not None, 'output has no ephemeral pubkey; not rewindable'
    # shared_secret = derive_ecdh_shared_secret(privkey_bytes, output.ephemeral_pubkey)
    # nonce = derive_rewind_nonce(shared_secret)
    # generator = derive_asset_tag(token_uid)
    # value, blinding, message = rewind_range_proof(output.range_proof, output.commitment, nonce, generator)
    # return ShieldedOutputSecrets(
    #     value=value,
    #     blinding_factor=blinding,
    #     message=message,
    #     token_uid=token_uid,
    # )
