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

import pytest
from pydantic import ValidationError

from hathor.feature_activation.settings import Settings


@pytest.mark.parametrize(
    'features',
    [
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=1,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            )
        ),
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=2 * 40320,
                timeout_height=3 * 40320,
                threshold=0,
                version='0.0.0'
            )
        )
    ]
)
def test_valid_settings(features):
    data = dict(features=features)
    Settings(**data)


@pytest.mark.parametrize(
    'features',
    [
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            )
        ),
        dict(
            NOP_FEATURE_1=dict(
                bit=0,
                start_height=0,
                timeout_height=40320,
                threshold=0,
                version='0.0.0'
            ),
            NOP_FEATURE_2=dict(
                bit=0,
                start_height=40320,
                timeout_height=2 * 40320,
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
                timeout_height=16 * 40320,
                threshold=0,
                version='0.0.0'
            )
        )
    ]
)
def test_conflicting_bits(features):
    with pytest.raises(ValidationError) as e:
        data = dict(features=features)
        Settings(**data)

    errors = e.value.errors()
    assert errors[0]['msg'] == 'One or more Features have the same bit configured for an overlapping interval'


@pytest.mark.parametrize(
    ['evaluation_interval', 'default_threshold', 'error'],
    [
        (10, 50, 'default_threshold must not be greater than evaluation_interval: 50 > 10'),
        (100, 101, 'default_threshold must not be greater than evaluation_interval: 101 > 100')
    ]
)
def test_default_threshold(evaluation_interval, default_threshold, error):
    with pytest.raises(ValidationError) as e:
        data = dict(evaluation_interval=evaluation_interval, default_threshold=default_threshold)
        Settings(**data)

    errors = e.value.errors()
    assert errors[0]['msg'] == error
