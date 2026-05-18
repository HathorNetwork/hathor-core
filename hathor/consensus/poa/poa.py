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

if TYPE_CHECKING:
    from hathor.transaction.poa import PoaBlock

BLOCK_WEIGHT_IN_TURN = 2.0
BLOCK_WEIGHT_OUT_OF_TURN = 1.0
SIGNER_ID_LEN = 2


def get_hashed_poa_data(block: PoaBlock) -> bytes:
    """Get the data to be signed for the Proof-of-Authority."""
    from hathor.transaction.vertex_parser import vertex_serializer
    poa_data = block.get_funds_struct()
    poa_data += vertex_serializer.serialize_block_base_graph(block)  # Block-level graph without poa fields
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


def get_signer_index_distance(*, settings: PoaSettings, signer_index: int, height: int) -> int:
    """Considering a block height, return the signer index distance to that block. When the distance is 0, it means it
    is the signer's turn."""
    active_signers = get_active_signers(settings, height)
    expected_index = height % len(active_signers)
    signers = get_active_signers(settings, height)
    index_distance = (signer_index - expected_index) % len(signers)
    assert 0 <= index_distance < len(signers)
    return index_distance


def calculate_weight(settings: PoaSettings, block: PoaBlock, signer_index: int) -> float:
    """Return the weight for the given block and signer."""
    index_distance = get_signer_index_distance(settings=settings, signer_index=signer_index, height=block.get_height())
    return BLOCK_WEIGHT_IN_TURN if index_distance == 0 else BLOCK_WEIGHT_OUT_OF_TURN / index_distance


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
    hashed_poa_data = get_hashed_poa_data(block)

    for signer_index, public_key_bytes in enumerate(active_signers):
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
