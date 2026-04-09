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

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
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
        signature_validation = poa.verify_poa_signature(poa_settings, block)
        if not isinstance(signature_validation, poa.ValidSignature):
            raise PoaValidationError('invalid PoA signature')

        # validate block weight is in turn
        expected_weight = poa.calculate_weight(poa_settings, block, signature_validation.signer_index)
        if block.weight != expected_weight:
            raise PoaValidationError(f'block weight is {block.weight}, expected {expected_weight}')
