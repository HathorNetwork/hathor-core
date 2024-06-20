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
from hathor.consensus.poa.poa_signer import PoaSigner
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

        # validate block rewards
        if block.outputs:
            raise PoaValidationError('blocks must not have rewards in a PoA network')

        # validate that the signature is valid
        sorted_signers = sorted(poa_settings.signers)
        signer_index: int | None = None

        for i, public_key_bytes in enumerate(sorted_signers):
            if self._verify_poa_signature(block, public_key_bytes):
                signer_index = i
                break

        if signer_index is None:
            raise PoaValidationError('invalid PoA signature')

        # validate block weight is in turn
        expected_weight = poa.calculate_weight(poa_settings, block, signer_index)
        if block.weight != expected_weight:
            raise PoaValidationError(f'block weight is {block.weight}, expected {expected_weight}')

    @staticmethod
    def _verify_poa_signature(block: PoaBlock, public_key_bytes: bytes) -> bool:
        """Return whether the provided public key was used to sign the block Proof-of-Authority."""
        signer_id = PoaSigner.get_poa_signer_id(public_key_bytes)
        if block.signer_id != signer_id:
            return False

        public_key = get_public_key_from_bytes_compressed(public_key_bytes)
        hashed_poa_data = poa.get_hashed_poa_data(block)
        try:
            public_key.verify(block.signature, hashed_poa_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True
