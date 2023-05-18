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
from typing import Any, Dict, List, Optional, Tuple

from pydantic import Field, NonNegativeInt, PositiveInt, validator

from hathor.feature_activation.model.criteria import Criteria
from hathor.utils.pydantic import BaseModel


class Settings(BaseModel, validate_all=True):
    """Feature Activation settings."""

    # The number of blocks in the feature activation evaluation interval.
    # Equivalent to 14 days (40320 * 30 seconds = 14 days)
    evaluation_interval: PositiveInt = 40320

    # The number of bits used in the first byte of a block's version field. The 4 left-most bits are not used.
    max_signal_bits: int = Field(ge=1, le=8, default=4)

    # Specifies the default minimum number of blocks per evaluation interval required to activate a feature.
    # Usually calculated from a percentage of evaluation_interval.
    default_threshold: NonNegativeInt = 36288  # 36288 = 90% of evaluation_interval (40320)

    # List of criteria for all features that participate in the feature activation process for a network,
    # past or future, activated or not. Features should NOT be removed from this list, and neither their
    # values changed, to preserve history.
    features: List[Criteria] = []

    @validator('evaluation_interval')
    def _process_evaluation_interval(cls, evaluation_interval: int) -> int:
        """Sets the evaluation_interval on Criteria."""
        Criteria.evaluation_interval = evaluation_interval
        return evaluation_interval

    @validator('max_signal_bits')
    def _process_max_signal_bits(cls, max_signal_bits: int) -> int:
        """Sets the max_signal_bits on Criteria."""
        Criteria.max_signal_bits = max_signal_bits
        return max_signal_bits

    @validator('default_threshold')
    def _validate_default_threshold(cls, default_threshold: int, values: Dict[str, Any]) -> int:
        """Validates that the default_threshold is not greater than the evaluation_interval."""
        if default_threshold > values.get('evaluation_interval', float('-inf')):
            raise ValueError('default_threshold must not be greater than evaluation_interval')

        return default_threshold

    @validator('features')
    def _validate_features(cls, features: List[Criteria]) -> List[Criteria]:
        """Validates all configured features."""
        _validate_duplicate_names(features)
        _validate_conflicting_bits(features)
        return features


def _validate_duplicate_names(features: List[Criteria]) -> None:
    """Validates that no two features share the same name."""
    feature_names = [criteria.name for criteria in features]

    if len(feature_names) != len(set(feature_names)):
        raise ValueError('Feature names should be unique')


def _validate_conflicting_bits(features: List[Criteria]) -> None:
    """
    Validates that a bit is only reused if the start_height of a new feature is
    greater than the timeout_height of the previous feature that used that bit.
    """
    intervals_by_bit = _get_intervals_by_bit(features)
    intervals_has_overlaps = [
        _has_any_overlap(intervals)
        for intervals in intervals_by_bit.values()
    ]

    if any(intervals_has_overlaps):
        raise ValueError(
            'One or more Features have the same bit configured for an overlapping interval'
        )


def _get_intervals_by_bit(features: List[Criteria]) -> Dict[int, List[Tuple[int, int]]]:
    """Returns a list of (start_height, timeout_height) intervals for all features, grouped by bit."""
    intervals_by_bit: Dict[int, List[Tuple[int, int]]] = defaultdict(list)

    for criteria in features:
        intervals = intervals_by_bit[criteria.bit]
        intervals.append((criteria.start_height, criteria.timeout_height))

    return intervals_by_bit


def _has_any_overlap(intervals: List[Tuple[int, int]]) -> bool:
    """Takes a list of intervals and returns whether any intervals overlap.

    >>> _has_any_overlap([])
    False
    >>> _has_any_overlap([(0, 10)])
    False
    >>> _has_any_overlap([(0, 10), (11, 20)])
    False
    >>> _has_any_overlap([(0, 10), (10, 20)])
    True
    >>> _has_any_overlap([(0, 10), (20, 30), (15, 25)])
    True
    """
    sorted_intervals = sorted(intervals, key=lambda interval: interval[0])
    previous_end: Optional[int] = None

    for current_begin, current_end in sorted_intervals:
        if previous_end is not None and current_begin <= previous_end:
            return True

        previous_end = current_end

    return False
