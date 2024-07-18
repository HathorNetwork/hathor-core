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


def is_in_turn(*, settings: PoaSettings, height: int, signer_index: int) -> bool:
    """Return whether the given signer is in turn for the given height."""
    return height % len(settings.signers) == signer_index


def calculate_weight(settings: PoaSettings, block: PoaBlock, signer_index: int) -> float:
    """Return the weight for the given block and signer."""
    is_in_turn_flag = is_in_turn(settings=settings, height=block.get_height(), signer_index=signer_index)
    return BLOCK_WEIGHT_IN_TURN if is_in_turn_flag else BLOCK_WEIGHT_OUT_OF_TURN


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
    sorted_signers = sorted(settings.signers)
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
