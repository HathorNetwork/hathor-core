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
from typing import Dict, List, Optional, Tuple

from hathor.feature_activation.exception import InvalidFeaturesConfigurationException
from hathor.feature_activation.model.criteria import Criteria


def validate_feature_list(features: List[Criteria]) -> None:
    """Validates a list of features."""
    _validate_duplicate_names(features)
    _validate_conflicting_bits(features)


def _validate_duplicate_names(features: List[Criteria]) -> None:
    """Validates that no two features share the same name."""
    feature_names = [criteria.name for criteria in features]

    if len(feature_names) != len(set(feature_names)):
        raise InvalidFeaturesConfigurationException('Feature names should be unique')


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
        raise InvalidFeaturesConfigurationException(
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
