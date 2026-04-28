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

"""Serialization/deserialization for individual shielded outputs."""

from __future__ import annotations

from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.int import decode_int, encode_int
from hathorlib.transaction.shielded_tx_output import (
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    MAX_RANGE_PROOF_SIZE,
    MAX_SHIELDED_OUTPUT_SCRIPT_SIZE,
    MAX_SURJECTION_PROOF_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    ShieldedOutput,
)


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


def _read_ephemeral_pubkey(deserializer: Deserializer) -> bytes:
    """Read 33 bytes; an all-zeros pubkey is normalized to b'' (not present)."""
    raw = bytes(deserializer.read_bytes(EPHEMERAL_PUBKEY_SIZE))
    return b'' if raw == b'\x00' * EPHEMERAL_PUBKEY_SIZE else raw


def _write_ephemeral_pubkey(serializer: Serializer, ephemeral_pubkey: bytes) -> None:
    """Write 33 bytes; an empty pubkey is written as 33 zero bytes."""
    serializer.write_bytes(ephemeral_pubkey if ephemeral_pubkey else b'\x00' * EPHEMERAL_PUBKEY_SIZE)


def serialize_shielded_output(serializer: Serializer, output: ShieldedOutput) -> None:
    """Serialize a shielded output.

    Format:
        mode(1) | commitment(33) | rp_len(2) | range_proof(var) | script_len(2) | script(var) |
        [if AMOUNT_ONLY]:    token_data(1)
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

    _write_ephemeral_pubkey(serializer, output.ephemeral_pubkey)


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
    _write_ephemeral_pubkey(serializer, output.ephemeral_pubkey)
