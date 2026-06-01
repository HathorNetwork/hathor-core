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
from typing import TYPE_CHECKING

from hathorlib.utils import int_to_bytes

if TYPE_CHECKING:
    from hathorlib.serialization import Deserializer, Serializer

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
    ephemeral_pubkey: bytes | None = None  # 33B compressed secp256k1 pubkey for ECDH recovery

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
    ephemeral_pubkey: bytes | None = None  # 33B compressed secp256k1 pubkey for ECDH recovery

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


def serialize_shielded_output(serializer: Serializer, output: ShieldedOutput, *, skip_proofs: bool = False) -> None:
    """Serialize a shielded output into the serializer.

    Format:
        mode(1) | commitment(33) | rp_len(2) | range_proof(var) | script_len(2) | script(var) |
        [if AMOUNT_ONLY]:  token_data(1)
        [if FULLY_SHIELDED]: asset_commitment(33) | sp_len(2) | surjection_proof(var)
        ephemeral_pubkey(33)  # all-zeros means 'not present'
    """
    serializer.write_bytes(int_to_bytes(int(output.mode()), 1))
    serializer.write_bytes(output.commitment)
    if not skip_proofs:
        serializer.write_bytes(int_to_bytes(len(output.range_proof), 2))
        serializer.write_bytes(output.range_proof)
    serializer.write_bytes(int_to_bytes(len(output.script), 2))
    serializer.write_bytes(output.script)

    if isinstance(output, AmountShieldedOutput):
        serializer.write_bytes(int_to_bytes(output.token_data, 1))
    elif isinstance(output, FullShieldedOutput):
        serializer.write_bytes(output.asset_commitment)
        if not skip_proofs:
            serializer.write_bytes(int_to_bytes(len(output.surjection_proof), 2))
            serializer.write_bytes(output.surjection_proof)

    # Ephemeral pubkey for ECDH-based recovery (always 33B; zeros = not present)
    serializer.write_bytes(output.ephemeral_pubkey if output.ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE)


def _deserialize_ephemeral_pubkey(deserializer: Deserializer) -> bytes | None:
    """Read the always-present 33B ephemeral pubkey field (all-zeros means 'not present')."""
    raw_ephemeral = bytes(deserializer.read_bytes(EPHEMERAL_PUBKEY_SIZE))
    return None if raw_ephemeral == b'\x00' * EPHEMERAL_PUBKEY_SIZE else raw_ephemeral


def deserialize_shielded_output(deserializer: Deserializer) -> ShieldedOutput:
    """Deserialize a single shielded output from the deserializer.

    Consumes exactly this output's bytes, leaving the deserializer positioned at the next one.
    """
    mode = OutputMode(deserializer.read_byte())
    commitment = bytes(deserializer.read_bytes(COMMITMENT_SIZE))

    (rp_len,) = deserializer.read_struct('!H')
    if rp_len > MAX_RANGE_PROOF_SIZE:
        raise ValueError(f'range proof size {rp_len} exceeds maximum {MAX_RANGE_PROOF_SIZE}')
    range_proof = bytes(deserializer.read_bytes(rp_len))

    (script_len,) = deserializer.read_struct('!H')
    if script_len > MAX_SHIELDED_OUTPUT_SCRIPT_SIZE:
        raise ValueError(f'script size {script_len} exceeds maximum {MAX_SHIELDED_OUTPUT_SCRIPT_SIZE}')
    script = bytes(deserializer.read_bytes(script_len))

    if mode == OutputMode.AMOUNT_ONLY:
        token_data = deserializer.read_byte()
        ephemeral_pubkey = _deserialize_ephemeral_pubkey(deserializer)
        return AmountShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            token_data=token_data,
            ephemeral_pubkey=ephemeral_pubkey,
        )

    if mode == OutputMode.FULLY_SHIELDED:
        asset_commitment = bytes(deserializer.read_bytes(ASSET_COMMITMENT_SIZE))
        (sp_len,) = deserializer.read_struct('!H')
        if sp_len > MAX_SURJECTION_PROOF_SIZE:
            raise ValueError(f'surjection proof size {sp_len} exceeds maximum {MAX_SURJECTION_PROOF_SIZE}')
        surjection_proof = bytes(deserializer.read_bytes(sp_len))
        ephemeral_pubkey = _deserialize_ephemeral_pubkey(deserializer)
        return FullShieldedOutput(
            commitment=commitment,
            range_proof=range_proof,
            script=script,
            asset_commitment=asset_commitment,
            surjection_proof=surjection_proof,
            ephemeral_pubkey=ephemeral_pubkey,
        )

    raise ValueError(f'Unknown shielded output mode: {int(mode)}')
