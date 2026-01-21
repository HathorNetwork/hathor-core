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

from typing import TYPE_CHECKING, Optional

from pydantic import ConfigDict, Field, NonNegativeInt, model_validator

from hathor import version
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.feature_activation.settings import Settings as FeatureSettings


class Criteria(BaseModel):
    """
    Represents the configuration for a certain feature activation criteria.

    Note: the to_validated() method must be called to perform all attribute validations.

    Attributes:
        evaluation_interval: the number of blocks in the feature activation evaluation interval.

        max_signal_bits: the number of bits used in the first byte of a block's version field.

        bit: which bit in the version field of the block is going to be used to signal the feature support by miners.

        start_height: the height of the first block at which this feature's activation process starts.

        timeout_height: the height of the first block at which this feature's activation process is over.

        threshold: the minimum number of blocks per evaluation interval required to activate the feature.

        minimum_activation_height: the height of the first block at which the feature is allowed to become active.

        lock_in_on_timeout: whether the feature should be activated even if the activation criteria are not met when
            the timeout_height is reached, effectively forcing activation.

        version: the client version of hathor-core at which this feature was defined.

        signal_support_by_default: the default miner support signal for this feature.
    """
    model_config = ConfigDict(validate_default=True)

    evaluation_interval: Optional[int] = None
    max_signal_bits: Optional[int] = None

    bit: NonNegativeInt
    start_height: NonNegativeInt
    timeout_height: NonNegativeInt
    threshold: Optional[NonNegativeInt] = None
    minimum_activation_height: NonNegativeInt = 0
    lock_in_on_timeout: bool = False
    version: str = Field(..., pattern=version.BUILD_VERSION_REGEX)
    signal_support_by_default: bool = False

    def to_validated(self, evaluation_interval: int, max_signal_bits: int) -> 'ValidatedCriteria':
        """Create a validated version of self, including attribute validations that have external dependencies."""
        return ValidatedCriteria(
            evaluation_interval=evaluation_interval,
            max_signal_bits=max_signal_bits,
            bit=self.bit,
            start_height=self.start_height,
            timeout_height=self.timeout_height,
            threshold=self.threshold,
            minimum_activation_height=self.minimum_activation_height,
            lock_in_on_timeout=self.lock_in_on_timeout,
            version=self.version,
            signal_support_by_default=self.signal_support_by_default
        )

    def get_threshold(self, feature_settings: 'FeatureSettings') -> int:
        """Returns the configured threshold, or the default threshold if it is None."""
        return self.threshold if self.threshold is not None else feature_settings.default_threshold


class ValidatedCriteria(Criteria):
    """
    Wrapper class for Criteria that holds its field validations. Can be created using Criteria.to_validated().
    """

    @model_validator(mode='after')
    def _validate_all(self) -> 'ValidatedCriteria':
        """Validates all criteria fields."""
        # Validate bit
        assert self.max_signal_bits is not None, 'max_signal_bits must be set'
        if self.bit >= self.max_signal_bits:
            raise ValueError(f'bit must be lower than max_signal_bits: {self.bit} >= {self.max_signal_bits}')

        # Validate evaluation_interval is set
        assert self.evaluation_interval is not None, 'evaluation_interval must be set'

        # Validate timeout_height
        minimum_timeout_height = self.start_height + 2 * self.evaluation_interval
        if self.timeout_height < minimum_timeout_height:
            raise ValueError(f'timeout_height must be at least two evaluation intervals after the start_height: '
                             f'{self.timeout_height} < {minimum_timeout_height}')

        # Validate threshold
        if self.threshold is not None and self.threshold > self.evaluation_interval:
            raise ValueError(
                f'threshold must not be greater than evaluation_interval: '
                f'{self.threshold} > {self.evaluation_interval}'
            )

        # Validate evaluation_interval multiples
        for field_name in ('start_height', 'timeout_height', 'minimum_activation_height'):
            value = getattr(self, field_name)
            if value % self.evaluation_interval != 0:
                raise ValueError(
                    f'{field_name} should be a multiple of evaluation_interval: '
                    f'{value} % {self.evaluation_interval} != 0'
                )

        return self
