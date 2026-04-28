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

from dataclasses import dataclass
from enum import IntEnum

from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.int import decode_int, encode_int

COMMITMENT_SIZE = 33
ASSET_COMMITMENT_SIZE = 33
EPHEMERAL_PUBKEY_SIZE = 33        # Compressed secp256k1 public key
MAX_RANGE_PROOF_SIZE = 3328       # Borromean @ 40-bit: 3213 B + headroom
MAX_SURJECTION_PROOF_SIZE = 4096  # Surjection proofs grow with input count
MAX_SHIELDED_OUTPUTS = 32         # Maximum number of shielded outputs per transaction
MAX_SHIELDED_OUTPUT_SCRIPT_SIZE = 1024  # Match settings.MAX_OUTPUT_SCRIPT_SIZE


class OutputMode(IntEnum):
    """Privacy level for an output."""
    TRANSPARENT = 0       # Standard TxOutput: amount, token ID, and script all visible
    AMOUNT_ONLY = 1       # Amount hidden, token ID visible (no surjection proof)
    FULLY_SHIELDED = 2    # Both amount and token ID hidden (surjection proof required)


@dataclass(slots=True, frozen=True)
class AmountShieldedOutput:
    """Amount hidden, token ID visible. No surjection proof needed."""
    commitment: bytes       # 33B Pedersen commitment (C = amount*H_token + r*G)
    range_proof: bytes      # ~3213B Borromean (40-bit)
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
    range_proof: bytes          # ~3213B Borromean (40-bit)
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
    asset_blinding_factor: bytes | None = None  # 32B for FullShieldedOutput, None for AmountShielded


# Union type for headers and verifiers
ShieldedOutput = AmountShieldedOutput | FullShieldedOutput


def _write_length_prefixed(serializer: Serializer, data: bytes) -> None:
    """Write a 2-byte big-endian length prefix followed by `data`."""
    encode_int(serializer, len(data), length=2, signed=False)
    serializer.write_bytes(data)


def _read_length_prefixed(deserializer: Deserializer, *, max_size: int, name: str) -> bytes:
    """Read a 2-byte big-endian length prefix followed by that many bytes.

    Rejects lengths above `max_size` so a malicious header can't make us
    allocate megabytes of buffer before failing.
    """
    length = decode_int(deserializer, length=2, signed=False)
    if length > max_size:
        raise ValueError(f'{name} size {length} exceeds maximum {max_size}')
    return bytes(deserializer.read_bytes(length))


def serialize_shielded_output(serializer: Serializer, output: ShieldedOutput) -> None:
    """Serialize a shielded output.

    Format:
        mode(1) | commitment(33) | rp_len(2) | range_proof(var) | script_len(2) | script(var) |
        [if AMOUNT_ONLY]:  token_data(1)
        [if FULLY_SHIELDED]: asset_commitment(33) | sp_len(2) | surjection_proof(var) |
        ephemeral_pubkey(33)
    """
    encode_int(serializer, output.mode(), length=1, signed=False)
    serializer.write_bytes(output.commitment)
    _write_length_prefixed(serializer, output.range_proof)
    _write_length_prefixed(serializer, output.script)

    if isinstance(output, AmountShieldedOutput):
        encode_int(serializer, output.token_data, length=1, signed=False)
    elif isinstance(output, FullShieldedOutput):
        serializer.write_bytes(output.asset_commitment)
        _write_length_prefixed(serializer, output.surjection_proof)

    # Ephemeral pubkey for ECDH-based recovery (always 33B; zeros = not present)
    ephemeral = output.ephemeral_pubkey if output.ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE
    serializer.write_bytes(ephemeral)


def deserialize_shielded_output(deserializer: Deserializer) -> ShieldedOutput:
    """Deserialize a shielded output."""
    mode = OutputMode(decode_int(deserializer, length=1, signed=False))
    commitment = bytes(deserializer.read_bytes(COMMITMENT_SIZE))
    range_proof = _read_length_prefixed(deserializer, max_size=MAX_RANGE_PROOF_SIZE, name='range proof')
    script = _read_length_prefixed(deserializer, max_size=MAX_SHIELDED_OUTPUT_SCRIPT_SIZE, name='script')

    if mode == OutputMode.AMOUNT_ONLY:
        token_data = decode_int(deserializer, length=1, signed=False)
        ephemeral_pubkey = _read_ephemeral_pubkey(deserializer)
        return AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )

    if mode == OutputMode.FULLY_SHIELDED:
        asset_commitment = bytes(deserializer.read_bytes(ASSET_COMMITMENT_SIZE))
        surjection_proof = _read_length_prefixed(
            deserializer, max_size=MAX_SURJECTION_PROOF_SIZE, name='surjection proof'
        )
        ephemeral_pubkey = _read_ephemeral_pubkey(deserializer)
        return FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=asset_commitment,
            surjection_proof=surjection_proof,
            ephemeral_pubkey=ephemeral_pubkey,
        )

    raise ValueError(f'Unknown shielded output mode: {mode}')


def _read_ephemeral_pubkey(deserializer: Deserializer) -> bytes:
    """Read 33 bytes; an all-zeros pubkey is normalized to b'' (not present)."""
    raw = bytes(deserializer.read_bytes(EPHEMERAL_PUBKEY_SIZE))
    return b'' if raw == b'\x00' * EPHEMERAL_PUBKEY_SIZE else raw


def serialize_sighash_bytes(serializer: Serializer, output: ShieldedOutput) -> None:
    """Serialize a shielded output's sighash subset.

    Includes commitment + mode + token_data/asset_commitment + script.
    Does NOT include proofs (range_proof, surjection_proof).

    Always includes ephemeral_pubkey in the sighash so a malleability attack
    that strips the ephemeral pubkey invalidates the signature; uses zero
    bytes if not present.
    """
    encode_int(serializer, output.mode(), length=1, signed=False)
    serializer.write_bytes(output.commitment)

    if isinstance(output, AmountShieldedOutput):
        encode_int(serializer, output.token_data, length=1, signed=False)
    elif isinstance(output, FullShieldedOutput):
        serializer.write_bytes(output.asset_commitment)

    serializer.write_bytes(output.script)

    ephemeral = output.ephemeral_pubkey if output.ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE
    serializer.write_bytes(ephemeral)


def get_sighash_bytes(output: ShieldedOutput) -> bytes:
    """Convenience wrapper: build a fresh serializer and return the sighash bytes."""
    serializer = Serializer.build_bytes_serializer()
    serialize_sighash_bytes(serializer, output)
    return bytes(serializer.finalize())
