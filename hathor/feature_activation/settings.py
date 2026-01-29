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

from collections import defaultdict
from typing import NamedTuple, Optional

from pydantic import ConfigDict, Field, NonNegativeInt, PositiveInt, model_validator

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.utils.pydantic import BaseModel


class Settings(BaseModel):
    """Feature Activation settings."""
    model_config = ConfigDict(validate_default=True)

    # The number of blocks in the feature activation evaluation interval.
    # Equivalent to 1 week (20160 * 30 seconds = 1 week)
    evaluation_interval: PositiveInt = 20_160

    # The number of bits used in the first byte of a block's version field. The 4 left-most bits are not used.
    max_signal_bits: int = Field(ge=1, le=8, default=4)

    # Specifies the default minimum number of blocks per evaluation interval required to activate a feature.
    # Usually calculated from a percentage of evaluation_interval.
    default_threshold: NonNegativeInt = 18_144  # 18144 = 90% of evaluation_interval (20160)

    # Dictionary of Feature enum to Criteria definition for all features that participate in the feature activation
    # process for a network, past or future, activated or not. Features should NOT be removed from this list, and
    # neither their values changed, to preserve history.
    features: dict[Feature, Criteria] = {}

    @model_validator(mode='after')
    def _validate_default_threshold(self) -> 'Settings':
        """Validates that the default_threshold is not greater than the evaluation_interval."""
        if self.default_threshold > self.evaluation_interval:
            raise ValueError(
                f'default_threshold must not be greater than evaluation_interval: '
                f'{self.default_threshold} > {self.evaluation_interval}'
            )
        return self

    @model_validator(mode='after')
    def _validate_features(self) -> 'Settings':
        """Validate Criteria by calling its to_validated() method, injecting the necessary attributes."""
        validated_features = {
            feature: criteria.to_validated(self.evaluation_interval, self.max_signal_bits)
            for feature, criteria in self.features.items()
        }
        # Use object.__setattr__ because the model is frozen
        object.__setattr__(self, 'features', validated_features)
        return self

    @model_validator(mode='after')
    def _validate_conflicting_bits(self) -> 'Settings':
        """
        Validates that a bit is only reused if the start_height of a new feature is
        greater than the timeout_height of the previous feature that used that bit.
        """
        intervals_by_bit = _get_intervals_by_bit(self.features)

        for intervals in intervals_by_bit.values():
            overlap = _find_overlap(intervals)

            if overlap:
                first, second = overlap
                raise ValueError(
                    f'At least one pair of Features have the same bit configured for an overlapping interval: '
                    f'{first.feature.value} and {second.feature.value}'
                )

        return self


class FeatureInterval(NamedTuple):
    begin: int
    end: int
    feature: Feature


def _get_intervals_by_bit(features: dict[Feature, Criteria]) -> dict[int, list[FeatureInterval]]:
    """Returns a list of (start_height, timeout_height) intervals for all features, grouped by bit."""
    intervals_by_bit: dict[int, list[FeatureInterval]] = defaultdict(list)

    for feature, criteria in features.items():
        intervals = intervals_by_bit[criteria.bit]
        interval = FeatureInterval(begin=criteria.start_height, end=criteria.timeout_height, feature=feature)
        intervals.append(interval)

    return intervals_by_bit


def _find_overlap(intervals: list[FeatureInterval]) -> Optional[tuple[FeatureInterval, FeatureInterval]]:
    """Takes a list of closed intervals and returns the first pair of intervals that overlap, or None otherwise."""
    sorted_intervals = sorted(intervals, key=lambda interval: interval[0])
    previous_interval: Optional[FeatureInterval] = None

    for current_interval in sorted_intervals:
        if previous_interval is not None and current_interval.begin <= previous_interval.end:
            return previous_interval, current_interval

        previous_interval = current_interval

    return None
