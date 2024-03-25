#  Copyright 2023 Hathor Labs
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
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_description import FeatureInfo
from hathor.transaction import MergeMinedBlock


class MergeMinedBlockVerifier:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

    def verify_aux_pow(self, block: MergeMinedBlock, feature_info: dict[Feature, FeatureInfo]) -> None:
        """ Verify auxiliary proof-of-work (for merged mining).
        """
        assert block.aux_pow is not None

        max_merkle_path_length = self._settings.OLD_MAX_MERKLE_PATH_LENGTH
        merkle_path_info = feature_info.get(Feature.INCREASE_MAX_MERKLE_PATH_LENGTH)

        if merkle_path_info and merkle_path_info.state.is_active():
            max_merkle_path_length = self._settings.NEW_MAX_MERKLE_PATH_LENGTH

        block.aux_pow.verify(block.get_base_hash(), max_merkle_path_length)
