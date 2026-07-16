# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction import MergeMinedBlock


class MergeMinedBlockVerifier:
    __slots__ = ('_settings', '_feature_service',)

    def __init__(self, *, settings: HathorSettings, feature_service: FeatureService):
        self._settings = settings
        self._feature_service = feature_service

    def verify_aux_pow(self, block: MergeMinedBlock) -> None:
        """ Verify auxiliary proof-of-work (for merged mining).
        """
        assert block.aux_pow is not None

        is_feature_active = self._feature_service.is_feature_active(
            vertex=block,
            feature=Feature.INCREASE_MAX_MERKLE_PATH_LENGTH
        )
        max_merkle_path_length = (
            self._settings.NEW_MAX_MERKLE_PATH_LENGTH if is_feature_active
            else self._settings.OLD_MAX_MERKLE_PATH_LENGTH
        )

        block.aux_pow.verify(block.get_mining_base_hash(), max_merkle_path_length)
