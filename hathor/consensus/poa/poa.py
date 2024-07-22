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

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.consensus.consensus_settings import PoaSettings
from hathor.crypto.util import get_public_key_from_bytes_compressed
from hathor.transaction import Block

if TYPE_CHECKING:
    from hathor.transaction.poa import PoaBlock

BLOCK_WEIGHT_IN_TURN = 2.0
BLOCK_WEIGHT_OUT_OF_TURN = 1.0
SIGNER_ID_LEN = 2


def get_hashed_poa_data(block: PoaBlock) -> bytes:
    """Get the data to be signed for the Proof-of-Authority."""
    poa_data = block.get_funds_struct()
    poa_data += Block.get_graph_struct(block)  # We call Block's to exclude poa fields
    poa_data += block.get_struct_nonce()
    hashed_poa_data = hashlib.sha256(poa_data).digest()
    return hashed_poa_data


def get_active_signers(settings: PoaSettings, height: int) -> list[bytes]:
    """Return a list of signers that are currently active considering the given block height."""
    active_signers = []
    for signer_settings in settings.signers:
        end_height = float('inf') if signer_settings.end_height is None else signer_settings.end_height

        if signer_settings.start_height <= height <= end_height:
            active_signers.append(signer_settings.public_key)

    return active_signers


def in_turn_signer_index(settings: PoaSettings, height: int) -> int:
    """Return the signer index that is in turn for the given height."""
    active_signers = get_active_signers(settings, height)
    return height % len(active_signers)


def calculate_weight(settings: PoaSettings, block: PoaBlock, signer_index: int) -> float:
    """Return the weight for the given block and signer."""
    expected_index = in_turn_signer_index(settings, block.get_height())
    return BLOCK_WEIGHT_IN_TURN if expected_index == signer_index else BLOCK_WEIGHT_OUT_OF_TURN


@dataclass(frozen=True, slots=True)
class InvalidSignature:
    pass


@dataclass(frozen=True, slots=True)
class ValidSignature:
    signer_index: int
    public_key: bytes


def verify_poa_signature(settings: PoaSettings, block: PoaBlock) -> InvalidSignature | ValidSignature:
    """Return whether the provided public key was used to sign the block Proof-of-Authority."""
    from hathor.consensus.poa import PoaSigner
    active_signers = get_active_signers(settings, block.get_height())
    sorted_signers = sorted(active_signers)
    hashed_poa_data = get_hashed_poa_data(block)

    for signer_index, public_key_bytes in enumerate(sorted_signers):
        signer_id = PoaSigner.get_poa_signer_id(public_key_bytes)
        if block.signer_id != signer_id:
            # this is not our signer
            continue

        public_key = get_public_key_from_bytes_compressed(public_key_bytes)
        try:
            public_key.verify(block.signature, hashed_poa_data, ec.ECDSA(hashes.SHA256()))
        except CryptographyInvalidSignature:
            # the signer_id is correct, but not the signature
            continue
        # the signer and signature are valid!
        return ValidSignature(signer_index, public_key_bytes)

    return InvalidSignature()
