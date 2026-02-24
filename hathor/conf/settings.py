# Copyright 2021 Hathor Labs
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
from typing import Any, Union

from pydantic import ConfigDict, field_validator, model_validator
from typing_extensions import Self

from hathor.checkpoint import Checkpoint
from hathor.consensus.consensus_settings import ConsensusSettings, PowSettings
from hathor.feature_activation.settings import Settings as FeatureActivationSettings
from hathorlib.conf.settings import HathorSettings as LibSettings

DECIMAL_PLACES = 2

GENESIS_TOKEN_UNITS = 1 * (10 ** 9)  # 1B
GENESIS_TOKENS = GENESIS_TOKEN_UNITS * (10 ** DECIMAL_PLACES)  # 100B

HATHOR_TOKEN_UID: bytes = b'\x00'


class HathorSettings(LibSettings):
    model_config = ConfigDict(extra='forbid')

    # Block checkpoints
    CHECKPOINTS: list[Checkpoint] = []

    @field_validator('CHECKPOINTS', mode='before')
    @classmethod
    def _parse_checkpoints(cls, checkpoints: Union[dict[int, str], list[Checkpoint]]) -> list[Checkpoint]:
        """Parse a dictionary of raw checkpoint data into a list of checkpoints."""
        if isinstance(checkpoints, dict):
            return [
                Checkpoint(height, bytes.fromhex(_hash))
                for height, _hash in checkpoints.items()
            ]

        if not isinstance(checkpoints, list):
            raise TypeError(f'expected \'dict[int, str]\' or \'list[Checkpoint]\', got {checkpoints}')

        return checkpoints

    # All settings related to Feature Activation
    FEATURE_ACTIVATION: FeatureActivationSettings = FeatureActivationSettings()

    @field_validator('FEATURE_ACTIVATION', mode='before')
    @classmethod
    def parse_feature_activation(cls, v: dict[str, Any]) -> FeatureActivationSettings:
        if isinstance(v, dict):
            return FeatureActivationSettings.model_validate(v)
        else:
            return v

    # The consensus algorithm protocol settings.
    CONSENSUS_ALGORITHM: ConsensusSettings = PowSettings()

    @model_validator(mode='after')
    def _validate_consensus_algorithm(self) -> Self:
        """Validate that if Proof-of-Authority is enabled, block rewards must not be set."""
        consensus_algorithm = self.CONSENSUS_ALGORITHM
        if consensus_algorithm.is_pow():
            return self

        if (self.BLOCKS_PER_HALVING is not None or
            self.INITIAL_TOKEN_UNITS_PER_BLOCK != 0 or
                self.MINIMUM_TOKEN_UNITS_PER_BLOCK != 0):
            raise ValueError('PoA networks do not support block rewards')
        return self
