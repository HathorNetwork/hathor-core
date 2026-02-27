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

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

COMMITMENT_SIZE = 33
ASSET_COMMITMENT_SIZE = 33
EPHEMERAL_PUBKEY_SIZE = 33        # Compressed secp256k1 public key
MAX_RANGE_PROOF_SIZE = 1024       # Valid Bulletproofs are ~675 bytes
MAX_SURJECTION_PROOF_SIZE = 4096  # Surjection proofs grow with input count
MAX_SHIELDED_OUTPUTS = 32         # Maximum number of shielded outputs per transaction
MAX_SHIELDED_OUTPUT_SCRIPT_SIZE = 1024  # Match settings.MAX_OUTPUT_SCRIPT_SIZE (VULN-001)


class OutputMode(IntEnum):
    """Privacy level for an output."""
    TRANSPARENT = 0       # Standard TxOutput: amount, token ID, and script all visible
    AMOUNT_ONLY = 1       # Amount hidden, token ID visible (no surjection proof)
    FULLY_SHIELDED = 2    # Both amount and token ID hidden (surjection proof required)


@dataclass(slots=True, frozen=True)
class AmountShieldedOutput:
    """Amount hidden, token ID visible. No surjection proof needed."""
    commitment: bytes       # 33B Pedersen commitment (C = amount*H_token + r*G)
    range_proof: bytes      # ~675B Bulletproof
    script: bytes           # Locking script
    token_data: int         # Token index (like TxOutput.token_data)
    ephemeral_pubkey: bytes = b''  # 33B compressed secp256k1 pubkey for ECDH recovery

    @staticmethod
    def mode() -> OutputMode:
        return OutputMode.AMOUNT_ONLY


@dataclass(slots=True, frozen=True)
class FullShieldedOutput:
    """Both amount and token type hidden. Surjection proof required."""
    commitment: bytes           # 33B Pedersen commitment
    range_proof: bytes          # ~675B Bulletproof
    script: bytes               # Locking script
    asset_commitment: bytes     # 33B blinded asset tag (A = H_token + r_asset*G)
    surjection_proof: bytes     # Variable, asset surjection proof
    ephemeral_pubkey: bytes = b''  # 33B compressed secp256k1 pubkey for ECDH recovery

    @staticmethod
    def mode() -> OutputMode:
        return OutputMode.FULLY_SHIELDED


@dataclass(slots=True, frozen=True)
class ShieldedOutputSecrets:
    """Recovered secrets from a shielded output via ECDH rewind."""
    value: int
    blinding_factor: bytes
    message: bytes
    token_uid: bytes  # Recovered or derived token UID


# Union type for headers and verifiers
ShieldedOutput = AmountShieldedOutput | FullShieldedOutput


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

    # For FullShieldedOutput, token UID is embedded in the message
    if isinstance(output, FullShieldedOutput) and len(message) >= 32:
        token_uid = bytes(message[:32])

    return ShieldedOutputSecrets(
        value=value,
        blinding_factor=blinding_factor,
        message=message,
        token_uid=token_uid,
    )


def serialize_shielded_output(output: ShieldedOutput) -> bytes:
    """Serialize a shielded output to bytes.

    Format:
        mode(1) | commitment(33) | rp_len(2) | range_proof(var) | script_len(2) | script(var) |
        [if AMOUNT_ONLY]:  token_data(1)
        [if FULLY_SHIELDED]: asset_commitment(33) | sp_len(2) | surjection_proof(var)
    """
    parts: list[bytes] = []
    parts.append(struct.pack('!B', output.mode()))
    parts.append(output.commitment)
    parts.append(struct.pack('!H', len(output.range_proof)))
    parts.append(output.range_proof)
    parts.append(struct.pack('!H', len(output.script)))
    parts.append(output.script)

    if isinstance(output, AmountShieldedOutput):
        parts.append(struct.pack('!B', output.token_data))
    elif isinstance(output, FullShieldedOutput):
        parts.append(output.asset_commitment)
        parts.append(struct.pack('!H', len(output.surjection_proof)))
        parts.append(output.surjection_proof)

    # Ephemeral pubkey for ECDH-based recovery (always 33B; zeros = not present)
    parts.append(output.ephemeral_pubkey if output.ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE)

    return b''.join(parts)


def deserialize_shielded_output(buf: bytes | memoryview) -> tuple[ShieldedOutput, bytes]:
    """Deserialize a shielded output from bytes.

    Returns (output, remaining_bytes).
    """
    view = memoryview(buf) if not isinstance(buf, memoryview) else buf
    offset = 0

    mode_byte = view[offset]
    offset += 1
    mode = OutputMode(mode_byte)

    commitment = bytes(view[offset:offset + COMMITMENT_SIZE])
    offset += COMMITMENT_SIZE
    if len(commitment) != COMMITMENT_SIZE:
        raise ValueError(
            f'truncated commitment: expected {COMMITMENT_SIZE} bytes, got {len(commitment)}'
        )

    (rp_len,) = struct.unpack_from('!H', view, offset)
    offset += 2
    if rp_len > MAX_RANGE_PROOF_SIZE:
        raise ValueError(
            f'range proof size {rp_len} exceeds maximum {MAX_RANGE_PROOF_SIZE}'
        )
    range_proof = bytes(view[offset:offset + rp_len])
    offset += rp_len
    if len(range_proof) != rp_len:
        raise ValueError(
            f'truncated range proof: expected {rp_len} bytes, got {len(range_proof)}'
        )

    (script_len,) = struct.unpack_from('!H', view, offset)
    offset += 2
    if script_len > MAX_SHIELDED_OUTPUT_SCRIPT_SIZE:
        raise ValueError(
            f'script size {script_len} exceeds maximum {MAX_SHIELDED_OUTPUT_SCRIPT_SIZE}'
        )
    script = bytes(view[offset:offset + script_len])
    offset += script_len
    if len(script) != script_len:
        raise ValueError(
            f'truncated script: expected {script_len} bytes, got {len(script)}'
        )

    if mode == OutputMode.AMOUNT_ONLY:
        token_data = view[offset]
        offset += 1

        # Read ephemeral pubkey (always 33B; zeros = not present)
        raw_ephemeral = bytes(view[offset:offset + EPHEMERAL_PUBKEY_SIZE])
        offset += EPHEMERAL_PUBKEY_SIZE
        if len(raw_ephemeral) != EPHEMERAL_PUBKEY_SIZE:
            raise ValueError(
                f'truncated ephemeral_pubkey: expected {EPHEMERAL_PUBKEY_SIZE} bytes, '
                f'got {len(raw_ephemeral)}'
            )
        ephemeral_pubkey = b'' if raw_ephemeral == b'\x00' * EPHEMERAL_PUBKEY_SIZE else raw_ephemeral

        output: ShieldedOutput = AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    elif mode == OutputMode.FULLY_SHIELDED:
        asset_commitment = bytes(view[offset:offset + ASSET_COMMITMENT_SIZE])
        offset += ASSET_COMMITMENT_SIZE
        if len(asset_commitment) != ASSET_COMMITMENT_SIZE:
            raise ValueError(
                f'truncated asset_commitment: expected {ASSET_COMMITMENT_SIZE} bytes, '
                f'got {len(asset_commitment)}'
            )

        (sp_len,) = struct.unpack_from('!H', view, offset)
        offset += 2
        if sp_len > MAX_SURJECTION_PROOF_SIZE:
            raise ValueError(
                f'surjection proof size {sp_len} exceeds maximum {MAX_SURJECTION_PROOF_SIZE}'
            )
        surjection_proof = bytes(view[offset:offset + sp_len])
        offset += sp_len
        if len(surjection_proof) != sp_len:
            raise ValueError(
                f'truncated surjection proof: expected {sp_len} bytes, got {len(surjection_proof)}'
            )

        # Read ephemeral pubkey (always 33B; zeros = not present)
        raw_ephemeral = bytes(view[offset:offset + EPHEMERAL_PUBKEY_SIZE])
        offset += EPHEMERAL_PUBKEY_SIZE
        if len(raw_ephemeral) != EPHEMERAL_PUBKEY_SIZE:
            raise ValueError(
                f'truncated ephemeral_pubkey: expected {EPHEMERAL_PUBKEY_SIZE} bytes, '
                f'got {len(raw_ephemeral)}'
            )
        ephemeral_pubkey = b'' if raw_ephemeral == b'\x00' * EPHEMERAL_PUBKEY_SIZE else raw_ephemeral

        output = FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=asset_commitment,
            surjection_proof=surjection_proof,
            ephemeral_pubkey=ephemeral_pubkey,
        )
    else:
        raise ValueError(f'Unknown shielded output mode: {mode_byte}')

    return output, bytes(view[offset:])


def get_sighash_bytes(output: ShieldedOutput) -> bytes:
    """Return sighash bytes for a shielded output.

    Includes commitment + mode + token_data/asset_commitment + script.
    Does NOT include proofs (range_proof, surjection_proof).
    """
    parts: list[bytes] = []
    parts.append(struct.pack('!B', output.mode()))
    parts.append(output.commitment)

    if isinstance(output, AmountShieldedOutput):
        parts.append(struct.pack('!B', output.token_data))
    elif isinstance(output, FullShieldedOutput):
        parts.append(output.asset_commitment)

    parts.append(output.script)

    # Always include ephemeral pubkey in sighash to prevent malleability
    # where someone strips the ephemeral pubkey. Use zero bytes if not present.
    parts.append(output.ephemeral_pubkey if output.ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE)

    return b''.join(parts)
