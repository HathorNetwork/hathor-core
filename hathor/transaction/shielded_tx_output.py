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

"""Shielded transaction output models and serialization.

Canonical definitions live in hathorlib; this module re-exports them
for backward compatibility and adds ``recover_shielded_secrets`` which
depends on hathor-core crypto.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Re-export canonical definitions from hathorlib
from hathorlib.transaction.shielded_tx_output import (  # noqa: F401
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    MAX_RANGE_PROOF_SIZE,
    MAX_SHIELDED_OUTPUT_SCRIPT_SIZE,
    MAX_SHIELDED_OUTPUTS,
    MAX_SURJECTION_PROOF_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    ShieldedOutput,
    ShieldedOutputSecrets,
    deserialize_shielded_output,
    get_sighash_bytes,
    serialize_shielded_output,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def recover_shielded_secrets(
    output: ShieldedOutput,
    private_key_bytes: bytes,
    get_token_uid: 'Callable[[int], bytes]',
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
    from hathor.crypto.shielded import derive_asset_tag, rewind_range_proof
    from hathor.crypto.shielded.ecdh import derive_ecdh_shared_secret, derive_rewind_nonce

    if not output.ephemeral_pubkey:
        raise ValueError('output has no ephemeral_pubkey for ECDH recovery')

    shared_secret = derive_ecdh_shared_secret(private_key_bytes, output.ephemeral_pubkey)
    nonce = derive_rewind_nonce(shared_secret)

    if isinstance(output, AmountShieldedOutput):
        token_uid = get_token_uid(output.token_data & 0x7F)
        generator = derive_asset_tag(token_uid)
    elif isinstance(output, FullShieldedOutput):
        generator = output.asset_commitment
        token_uid = b''  # Will be recovered from message
    else:
        raise ValueError(f'unknown shielded output type: {type(output).__name__}')

    value, blinding_factor, message = rewind_range_proof(
        output.range_proof, output.commitment, nonce, generator
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
