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

"""Shielded output data types and size constants.

Wire-format (de)serialization lives in
``hathorlib.vertex_parser._shielded_tx_output``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

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
