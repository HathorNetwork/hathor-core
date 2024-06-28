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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
from hathor.crypto.util import get_public_key_from_bytes_compressed
from hathor.transaction.exceptions import PoaValidationError
from hathor.transaction.poa import PoaBlock


class PoaBlockVerifier:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings):
        self._settings = settings

    def verify_poa(self, block: PoaBlock) -> None:
        """Validate the Proof-of-Authority."""
        poa_settings = self._settings.CONSENSUS_ALGORITHM
        assert isinstance(poa_settings, PoaSettings)

        parent_block = block.get_block_parent()
        if block.timestamp < parent_block.timestamp + self._settings.AVG_TIME_BETWEEN_BLOCKS:
            raise PoaValidationError(
                f'blocks must have at least {self._settings.AVG_TIME_BETWEEN_BLOCKS} seconds between them'
            )

        # validate block rewards
        if block.outputs:
            raise PoaValidationError('blocks must not have rewards in a PoA network')

        # validate that the signature is valid
        signer = poa.get_signer_index_and_public_key(poa_settings, block.signer_id)
        if signer is None:
            raise PoaValidationError('invalid PoA signature')

        signer_index, public_key_bytes = signer
        self._verify_poa_signature(block, public_key_bytes)

        # validate block weight is in turn
        expected_weight = poa.calculate_weight(poa_settings, block, signer_index)
        if block.weight != expected_weight:
            raise PoaValidationError(f'block weight is {block.weight}, expected {expected_weight}')

    @staticmethod
    def _verify_poa_signature(block: PoaBlock, public_key_bytes: bytes) -> bool:
        """Return whether the provided public key was used to sign the block Proof-of-Authority."""
        public_key = get_public_key_from_bytes_compressed(public_key_bytes)
        hashed_poa_data = poa.get_hashed_poa_data(block)
        try:
            public_key.verify(block.signature, hashed_poa_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True
