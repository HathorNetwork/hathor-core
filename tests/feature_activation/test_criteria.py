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
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from hathor.feature_activation.model.criteria import Criteria

Criteria.evaluation_interval = 1000
Criteria.max_signal_bits = 2

VALID_CRITERIA = dict(
    name='FEATURE_1',
    bit=0,
    start_height=1000,
    timeout_height=2000,
    threshold=0,
    minimum_activation_height=0,
    activate_on_timeout=False,
    version='0.0.0'
)


class TestFeature(Enum):
    FEATURE_1 = 1
    FEATURE_2 = 2


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize(
    'criteria',
    [
        VALID_CRITERIA,
        dict(
            name='FEATURE_1',
            bit=1,
            start_height=100_000,
            timeout_height=102_000,
            threshold=1000,
            minimum_activation_height=101_000,
            activate_on_timeout=True,
            version='0.52.3'
        )
    ]
)
def test_valid_criteria(criteria):
    Criteria(**criteria)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('name', ['FEATURE_O', 'SOME_OTHER_NAME'])
def test_unknown_name(name):
    criteria = VALID_CRITERIA | dict(name=name)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('name',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('bit', [-10, -1, 4, 10])
def test_bit(bit):
    criteria = VALID_CRITERIA | dict(bit=bit)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('bit',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('start_height', [-10, -1, 1, 45, 100])
def test_start_height(start_height):
    criteria = VALID_CRITERIA | dict(start_height=start_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('start_height',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('timeout_height', [-10, -1, 1, 45, 100, 40320])
def test_timeout_height(timeout_height):
    criteria = VALID_CRITERIA | dict(timeout_height=timeout_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('timeout_height',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('threshold', [-10, -1, 40321, 100000])
def test_threshold(threshold):
    criteria = VALID_CRITERIA | dict(threshold=threshold)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('threshold',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('minimum_activation_height', [-10, -1, 1, 45, 100, 10 * 40320])
def test_minimum_activation_height(minimum_activation_height):
    criteria = VALID_CRITERIA | dict(minimum_activation_height=minimum_activation_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('minimum_activation_height',)


@patch('hathor.feature_activation.model.criteria.Feature', TestFeature)
@pytest.mark.parametrize('version', ['0', 'alpha', '0.0'])
def test_version(version):
    criteria = VALID_CRITERIA | dict(version=version)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria)

    errors = e.value.errors()
    assert errors[0]['loc'] == ('version',)
