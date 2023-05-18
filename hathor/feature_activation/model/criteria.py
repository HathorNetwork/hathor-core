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

from typing import Any, ClassVar, Dict, Optional

from pydantic import Field, NonNegativeInt, validator

from hathor import version
from hathor.utils.pydantic import BaseModel


class Criteria(BaseModel, validate_all=True):
    """
    Represents the configuration for a certain feature activation criteria.

    Attributes:
        evaluation_interval: the number of blocks in the feature activation evaluation interval. Class variable.

        max_signal_bits: the number of bits used in the first byte of a block's version field. Class variable.

        bit: which bit in the version field of the block is going to be used to signal the feature support by miners.

        start_height: the height of the first block at which this feature's activation process starts.

        timeout_height: the height of the first block at which this feature's activation process is over.

        threshold: the minimum number of blocks per evaluation interval required to activate the feature.

        minimum_activation_height: the height of the first block at which the feature is allowed to become active.

        activate_on_timeout: whether the feature should be activated even if the activation criteria are not met when
            the timeout_height is reached, effectively forcing activation.

        version: the client version of hathor-core at which this feature was defined.
    """
    evaluation_interval: ClassVar[Optional[int]] = None
    max_signal_bits: ClassVar[Optional[int]] = None

    bit: NonNegativeInt
    start_height: NonNegativeInt
    timeout_height: NonNegativeInt
    threshold: Optional[NonNegativeInt] = None
    minimum_activation_height: NonNegativeInt = 0
    activate_on_timeout: bool = False
    version: str = Field(..., regex=version.BUILD_VERSION_REGEX)

    @validator('bit')
    def _validate_bit(cls, bit: int) -> int:
        """Validates that the bit is lower than the max_signal_bits."""
        assert Criteria.max_signal_bits is not None, 'Criteria.max_signal_bits must be set'

        if bit >= Criteria.max_signal_bits:
            raise ValueError(f'bit must be lower than max_signal_bits: {bit} >= {Criteria.max_signal_bits}')

        return bit

    @validator('timeout_height')
    def _validate_timeout_height(cls, timeout_height: int, values: Dict[str, Any]) -> int:
        """Validates that the timeout_height is greater than the start_height."""
        start_height = values.get('start_height')
        assert start_height is not None, 'start_height must be set'

        if timeout_height <= start_height:
            raise ValueError(f'timeout_height must be greater than start_height: {timeout_height} <= {start_height}')

        return timeout_height

    @validator('threshold')
    def _validate_threshold(cls, threshold: int) -> int:
        """Validates that the threshold is not greater than the evaluation_interval."""
        assert Criteria.evaluation_interval is not None, 'Criteria.evaluation_interval must be set'

        if threshold > Criteria.evaluation_interval:
            raise ValueError(
                f'threshold must not be greater than evaluation_interval: {threshold} > {Criteria.evaluation_interval}'
            )

        return threshold

    @validator('minimum_activation_height')
    def _validate_minimum_activation_height(cls, minimum_activation_height: int, values: Dict[str, Any]) -> int:
        """Validates that the minimum_activation_height is not greater than the timeout_height."""
        timeout_height = values.get('timeout_height')
        assert timeout_height is not None, 'timeout_height must be set'

        if minimum_activation_height > timeout_height:
            raise ValueError(
                f'minimum_activation_height must not be greater than timeout_height: '
                f'{minimum_activation_height} > {timeout_height}'
            )

        return minimum_activation_height

    @validator('start_height', 'timeout_height', 'minimum_activation_height')
    def _validate_evaluation_interval_multiple(cls, value: int) -> int:
        """Validates that the value is a multiple of evaluation_interval."""
        assert Criteria.evaluation_interval is not None, 'Criteria.evaluation_interval must be set'

        if value % Criteria.evaluation_interval != 0:
            raise ValueError(
                f'Should be a multiple of evaluation_interval: {value} % {Criteria.evaluation_interval} != 0'
            )

        return value
