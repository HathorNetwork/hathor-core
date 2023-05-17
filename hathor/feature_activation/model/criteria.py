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

from typing import Any, Dict, Optional

from pydantic import Field, validator

from hathor import version
from hathor.feature_activation import constants
from hathor.feature_activation.feature import Feature
from hathor.utils.pydantic import BaseModel


class Criteria(BaseModel):
    """
    Represents the configuration for a certain feature activation criteria.

    Attributes:
        name: a string representing the name of the feature.

        bit: which bit in the version field of the block is going to be used to signal the feature support by miners.

        start_height: the height of the first block at which this feature's activation process starts.

        timeout_height: the height of the first block at which this feature's activation process is over.

        threshold: the minimum number of blocks per evaluation interval required to activate the feature.

        minimum_activation_height: the height of the first block at which the feature is allowed to become active.

        activate_on_timeout: whether the feature should be activated even if the activation criteria are not met when
            the timeout_height is reached, effectively forcing activation.

        version: the client version of hathor-core at which this feature was defined.
    """

    name: str
    bit: int = Field(ge=0, lt=constants.MAX_SIGNAL_BITS)
    start_height: int = Field(ge=0, multiple_of=constants.EVALUATION_INTERVAL)
    timeout_height: int = Field(ge=0, multiple_of=constants.EVALUATION_INTERVAL)
    threshold: Optional[int] = Field(ge=0, le=constants.EVALUATION_INTERVAL, default=None)
    minimum_activation_height: int = Field(ge=0, multiple_of=constants.EVALUATION_INTERVAL, default=0)
    activate_on_timeout: bool = False
    version: str = Field(regex=version.BUILD_VERSION_REGEX)

    @validator('name')
    def _validate_name(cls, name: str) -> str:
        """Validates that the name exists."""
        valid_names = [feature.name for feature in Feature]

        if name not in valid_names:
            raise ValueError(f"Unknown Feature name: '{name}'. Should be one of {valid_names}")

        return name

    @validator('timeout_height')
    def _validate_timeout_height(cls, timeout_height: int, values: Dict[str, Any]) -> int:
        """Validate that the timeout_height is greater than the start_height."""
        if timeout_height <= values.get('start_height', float('inf')):
            raise ValueError('timeout_height must be greater than start_height')

        return timeout_height

    @validator('minimum_activation_height')
    def _validate_minimum_activation_height(cls, minimum_activation_height: int, values: Dict[str, Any]) -> int:
        """Validates that the minimum_activation_height is not greater than the timeout_height."""
        if minimum_activation_height > values.get('timeout_height', float('-inf')):
            raise ValueError('minimum_activation_height must not be greater than timeout_height')

        return minimum_activation_height
