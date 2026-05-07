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
from typing import TYPE_CHECKING, NewType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ConfigDict, Field, field_validator, model_validator

from hathor.consensus import poa
from hathor.crypto.util import (
    get_address_b58_from_public_key,
    get_private_key_from_bytes,
    get_public_key_bytes_compressed,
    get_public_key_from_bytes_compressed,
)
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.transaction.poa import PoaBlock


class PoaSignerFile(BaseModel):
    """Class that represents a Proof-of-Authority signer configuration file."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    private_key: ec.EllipticCurvePrivateKeyWithSerialization = Field(alias='private_key_hex')
    public_key: ec.EllipticCurvePublicKey = Field(alias='public_key_hex')
    address: str

    @field_validator('private_key', mode='before')
    @classmethod
    def _parse_private_key(cls, private_key_hex: str) -> ec.EllipticCurvePrivateKeyWithSerialization:
        """Parse a private key hex into a private key instance."""
        private_key_bytes = bytes.fromhex(private_key_hex)
        return get_private_key_from_bytes(private_key_bytes)

    @model_validator(mode='after')
    def _validate_keys_and_address(self) -> 'PoaSignerFile':
        """Validate that public key and address correspond to the private key."""
        actual_public_key = self.private_key.public_key()
        actual_public_key_bytes = get_public_key_bytes_compressed(actual_public_key)

        # Validate the provided public key matches the one derived from private key
        provided_public_key_bytes = get_public_key_bytes_compressed(self.public_key)
        if provided_public_key_bytes != actual_public_key_bytes:
            raise ValueError('invalid public key')

        if self.address != get_address_b58_from_public_key(actual_public_key):
            raise ValueError('invalid address')

        return self

    @field_validator('public_key', mode='before')
    @classmethod
    def _parse_public_key(cls, public_key_hex: str | ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
        """Parse public key hex to public key object."""
        if isinstance(public_key_hex, ec.EllipticCurvePublicKey):
            return public_key_hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        return get_public_key_from_bytes_compressed(public_key_bytes)

    def get_signer(self) -> PoaSigner:
        """Get a PoaSigner for this file."""
        return PoaSigner(self.private_key)


"""
The `PoaSignerId` is the first 2 bytes of the hashed public key of a signer(see `PoaSigner.get_poa_signer_id()`).
It is a non-unique ID that represents a signer and exists simply to skip unnecessary signature verifications during the
verification process of PoA blocks.
"""
PoaSignerId = NewType('PoaSignerId', bytes)


class PoaSigner:
    """Class that represents a Proof-of-Authority signer."""
    __slots__ = ('_private_key', '_signer_id')

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        public_key_bytes = get_public_key_bytes_compressed(private_key.public_key())
        self._signer_id = self.get_poa_signer_id(public_key_bytes)

    def sign_block(self, block: PoaBlock) -> None:
        """Sign the Proof-of-Authority for a block."""
        hashed_poa_data = poa.get_hashed_poa_data(block)
        signature = self._private_key.sign(hashed_poa_data, ec.ECDSA(hashes.SHA256()))
        block.signer_id = self._signer_id
        block.signature = signature

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        """Return this signer's public key."""
        return self._private_key.public_key()

    @staticmethod
    def get_poa_signer_id(compressed_public_key_bytes: bytes) -> PoaSignerId:
        """Get the PoaSignerId from the compressed public key bytes."""
        hashed_public_key = hashlib.sha256(compressed_public_key_bytes).digest()
        return PoaSignerId(hashed_public_key[:poa.SIGNER_ID_LEN])
