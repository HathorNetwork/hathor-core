# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
