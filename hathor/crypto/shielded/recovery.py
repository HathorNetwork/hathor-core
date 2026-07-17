# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""ECDH-based recovery of a shielded output's hidden secrets.

A recipient's wallet uses this to detect and decrypt its own shielded outputs: derive the ECDH
shared secret from the recipient's private key + the output's ephemeral pubkey, derive the rewind
nonce, and rewind the range proof to recover the hidden value/blinding-factor/message (and, for a
FullShieldedOutput, the hidden token uid + asset blinding factor carried in the message).

This bridges the (hathorlib) data model and the (hathor-core) crypto layer, so it lives here in
hathor.crypto.shielded rather than with the data model — it depends on the native crypto wrappers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.transaction.shielded_tx_output import (
    AmountShieldedOutput,
    FullShieldedOutput,
    ShieldedOutput,
    ShieldedOutputSecrets,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def recover_shielded_secrets(
    output: ShieldedOutput,
    private_key_bytes: bytes,
    get_token_uid: Callable[[int], bytes],
) -> ShieldedOutputSecrets:
    """Recover hidden values from a shielded output using ECDH + range proof rewind.

    Args:
        output: The shielded output to recover secrets from.
        private_key_bytes: The 32-byte secret key for ECDH.
        get_token_uid: Callback to resolve token_data index to token UID (e.g., tx.get_token_uid).

    Returns:
        ShieldedOutputSecrets with the recovered value, blinding factor, message, and token UID.

    Raises:
        ValueError: If ECDH recovery fails or the output has no ephemeral pubkey.
    """
    from hathor_ct_crypto import (
        derive_asset_tag,
        derive_ecdh_shared_secret,
        derive_rewind_nonce,
        rewind_range_proof,
    )

    if not output.ephemeral_pubkey:
        raise ValueError('output has no ephemeral_pubkey for ECDH recovery')

    shared_secret = derive_ecdh_shared_secret(
        private_key_bytes=private_key_bytes,
        peer_pubkey_bytes=output.ephemeral_pubkey,
    )
    nonce = derive_rewind_nonce(shared_secret)

    token_uid: bytes
    if isinstance(output, AmountShieldedOutput):
        from hathor.transaction import TxOutput
        token_uid = get_token_uid(output.token_data & TxOutput.TOKEN_INDEX_MASK)
        generator = derive_asset_tag(token_uid)
    elif isinstance(output, FullShieldedOutput):
        generator = output.asset_commitment
        # token_uid is bound below from the rewound message bytes.
    else:
        raise ValueError(f'unknown shielded output type: {type(output).__name__}')

    value, blinding_factor, message = rewind_range_proof(
        proof=output.range_proof,
        commitment=output.commitment,
        nonce=nonce,
        generator=generator,
    )

    asset_blinding_factor: bytes | None = None

    # For FullShieldedOutput, token UID and asset blinding factor are embedded in the message
    if isinstance(output, FullShieldedOutput):
        if len(message) < 64:
            raise ValueError(
                f'FullShieldedOutput message too short for recovery: expected >= 64 bytes '
                f'(32 token_uid + 32 asset_bf), got {len(message)}'
            )
        token_uid = bytes(message[:32])
        asset_blinding_factor = bytes(message[32:64])

    return ShieldedOutputSecrets(
        value=value,
        blinding_factor=blinding_factor,
        message=message,
        token_uid=token_uid,
        asset_blinding_factor=asset_blinding_factor,
    )
