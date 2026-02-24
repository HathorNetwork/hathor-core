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
from typing import Any

import pytest
from pydantic import ValidationError

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.settings import FeatureInterval, Settings as FeatureSettings, _find_overlap


@pytest.mark.parametrize(
    'features',
    [
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=1,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            )
        ),
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=3 * 40320,
                timeout_height=5 * 40320,
                threshold=0,
                version='0.0.0'
            )
        )
    ]
)
def test_valid_settings(features: dict[str, Any]) -> None:
    data = dict(features=features)
    FeatureSettings(**data)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    'features',
    [
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            )
        ),
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=80640,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=40320,
                timeout_height=3 * 40320,
                threshold=0,
                version='0.0.0'
            )
        ),
        dict(
            NOP_FEATURE_1=dict(
                bit=1,
                start_height=10 * 40320,
                timeout_height=20 * 40320,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=1,
                start_height=15 * 40320,
                timeout_height=17 * 40320,
                threshold=0,
                version='0.0.0'
            )
        )
    ]
)
def test_conflicting_bits(features: list[dict[str, Any]]) -> None:
    with pytest.raises(ValidationError) as e:
        data = dict(features=features)
        FeatureSettings(**data)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == 'Value error, At least one pair of Features have the same bit configured for an ' \
                               'overlapping interval: NOP_FEATURE_1 and NOP_FEATURE_2'


@pytest.mark.parametrize(
    ['evaluation_interval', 'default_threshold', 'error'],
    [
        (10, 50, 'Value error, default_threshold must not be greater than evaluation_interval: 50 > 10'),
        (100, 101, 'Value error, default_threshold must not be greater than evaluation_interval: 101 > 100')
    ]
)
def test_default_threshold(evaluation_interval: int, default_threshold: int, error: str) -> None:
    with pytest.raises(ValidationError) as e:
        data = dict(evaluation_interval=evaluation_interval, default_threshold=default_threshold)
        FeatureSettings(**data)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize(
    ['intervals', 'expected'],
    [
        ([], None),
        ([FeatureInterval(0, 10, Feature.NOP_FEATURE_1)], None),
        ([FeatureInterval(0, 10, Feature.NOP_FEATURE_1), FeatureInterval(11, 20, Feature.NOP_FEATURE_1)], None),
        (
            [FeatureInterval(0, 10, Feature.NOP_FEATURE_1), FeatureInterval(10, 20, Feature.NOP_FEATURE_1)],
            (FeatureInterval(0, 10, Feature.NOP_FEATURE_1), FeatureInterval(10, 20, Feature.NOP_FEATURE_1))
        ),
        (
            [
                FeatureInterval(0, 10, Feature.NOP_FEATURE_1),
                FeatureInterval(20, 30, Feature.NOP_FEATURE_1),
                FeatureInterval(15, 25, Feature.NOP_FEATURE_1)
            ],
            (FeatureInterval(15, 25, Feature.NOP_FEATURE_1), FeatureInterval(20, 30, Feature.NOP_FEATURE_1))
        )
    ]
)
def test_find_overlap(intervals: list[FeatureInterval], expected: tuple[FeatureInterval, FeatureInterval]) -> None:
    assert expected == _find_overlap(intervals)
