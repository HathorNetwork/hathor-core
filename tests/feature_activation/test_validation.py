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

from enum import Enum
from typing import List

import pytest

from hathor.feature_activation.exception import InvalidFeaturesConfigurationException
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.validation import validate_feature_list


class TestFeature(Enum):
    FEATURE_1 = 1
    FEATURE_2 = 2


@pytest.mark.parametrize(
    'features',
    [
        [
            Criteria.construct(
                name='FEATURE_1',
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            Criteria.construct(
                name='FEATURE_2',
                bit=1,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            )
        ],
        [
            Criteria.construct(
                name='FEATURE_1',
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            Criteria.construct(
                name='FEATURE_2',
                bit=0,
                start_height=2 * 40320,
                timeout_height=3 * 40320,
                threshold=0,
                version='0.0.0'
            )
        ]
    ]
)
def test_valid_feature_list(features: List[Criteria]) -> None:
    validate_feature_list(features)


def test_duplicate_names():
    features = [
        Criteria.construct(
            name='FEATURE_1',
            bit=0,
            start_height=0,
            timeout_height=40320,
            threshold=0,
            version='0.0.0'
        ),
        Criteria.construct(
            name='FEATURE_1',
            bit=1,
            start_height=0,
            timeout_height=40320,
            threshold=0,
            version='0.0.0'
        )
    ]

    with pytest.raises(InvalidFeaturesConfigurationException) as e:
        validate_feature_list(features)

    assert str(e.value) == 'Feature names should be unique'


@pytest.mark.parametrize(
    'features',
    [
        [
            Criteria.construct(
                name='FEATURE_1',
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            Criteria.construct(
                name='FEATURE_2',
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            )
        ],
        [
            Criteria.construct(
                name='FEATURE_1',
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            Criteria.construct(
                name='FEATURE_2',
                bit=0,
                start_height=40320,
                timeout_height=2 * 40320,
                threshold=0,
                version='0.0.0'
            )
        ],
        [
            Criteria.construct(
                name='FEATURE_1',
                bit=1,
                start_height=10 * 40320,
                timeout_height=20 * 40320,
                threshold=0,
                version='0.0.0'
            ),
            Criteria.construct(
                name='FEATURE_2',
                bit=1,
                start_height=15 * 40320,
                timeout_height=16 * 40320,
                threshold=0,
                version='0.0.0'
            )
        ]
    ]
)
def test_conflicting_bits(features: List[Criteria]) -> None:
    with pytest.raises(InvalidFeaturesConfigurationException) as e:
        validate_feature_list(features)

    assert str(e.value) == 'One or more Features have the same bit configured for an overlapping interval'
