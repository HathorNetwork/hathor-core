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

from hathor.feature_activation.model.criteria import Criteria

VALID_CRITERIA = dict(
    bit=0,
    start_height=1000,
    timeout_height=3000,
    threshold=0,
    minimum_activation_height=0,
    lock_in_on_timeout=False,
    version='0.0.0'
)


@pytest.mark.parametrize(
    'criteria',
    [
        VALID_CRITERIA,
        dict(
            bit=1,
            start_height=100_000,
            timeout_height=102_000,
            threshold=1000,
            minimum_activation_height=101_000,
            lock_in_on_timeout=True,
            version='0.52.3'
        )
    ]
)
def test_valid_criteria(criteria: dict[str, Any]) -> None:
    Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)


@pytest.mark.parametrize(
    ['bit', 'error'],
    [
        (-10, 'ensure this value is greater than or equal to 0'),
        (-1, 'ensure this value is greater than or equal to 0'),
        (2, 'bit must be lower than max_signal_bits: 2 >= 2'),
        (10, 'bit must be lower than max_signal_bits: 10 >= 2')
    ]
)
def test_bit(bit: int, error: str) -> None:
    criteria = VALID_CRITERIA | dict(bit=bit)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize(
    ['start_height', 'error'],
    [
        (-10, 'ensure this value is greater than or equal to 0'),
        (-1, 'ensure this value is greater than or equal to 0'),
        (1, 'Should be a multiple of evaluation_interval: 1 % 1000 != 0'),
        (45, 'Should be a multiple of evaluation_interval: 45 % 1000 != 0'),
        (100, 'Should be a multiple of evaluation_interval: 100 % 1000 != 0')
    ]
)
def test_start_height(start_height: int, error: str) -> None:
    criteria = VALID_CRITERIA | dict(start_height=start_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize(
    ['timeout_height', 'error'],
    [
        (-10, 'ensure this value is greater than or equal to 0'),
        (-1, 'ensure this value is greater than or equal to 0'),
        (1, 'timeout_height must be at least two evaluation intervals after the start_height: 1 < 3000'),
        (45, 'timeout_height must be at least two evaluation intervals after the start_height: 45 < 3000'),
        (100, 'timeout_height must be at least two evaluation intervals after the start_height: 100 < 3000'),
        (3111, 'Should be a multiple of evaluation_interval: 3111 % 1000 != 0')
    ]
)
def test_timeout_height(timeout_height: int, error: str) -> None:
    criteria = VALID_CRITERIA | dict(timeout_height=timeout_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize(
    ['threshold', 'error'],
    [
        (-10, 'ensure this value is greater than or equal to 0'),
        (-1, 'ensure this value is greater than or equal to 0'),
        (1001, 'threshold must not be greater than evaluation_interval: 1001 > 1000'),
        (100000, 'threshold must not be greater than evaluation_interval: 100000 > 1000')
    ]
)
def test_threshold(threshold: int, error: str) -> None:
    criteria = VALID_CRITERIA | dict(threshold=threshold)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize(
    ['minimum_activation_height', 'error'],
    [
        (-10, 'ensure this value is greater than or equal to 0'),
        (-1, 'ensure this value is greater than or equal to 0'),
        (1, 'Should be a multiple of evaluation_interval: 1 % 1000 != 0'),
        (45, 'Should be a multiple of evaluation_interval: 45 % 1000 != 0'),
        (100, 'Should be a multiple of evaluation_interval: 100 % 1000 != 0'),
    ]
)
def test_minimum_activation_height(minimum_activation_height: int, error: str) -> None:
    criteria = VALID_CRITERIA | dict(minimum_activation_height=minimum_activation_height)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == error


_invalid_version_msg = r'string does not match regex "^(\d+\.\d+\.\d+(-(rc|alpha|beta)\.\d+)?|nightly-[a-f0-9]{7,8})$"'


@pytest.mark.parametrize(
    ['version'],
    [
        ('0',),
        ('alpha',),
        ('0.0',),
        ('0.0.0-',),
        ('0.1.0-alpha',),
        ('0.1.0-alpha.x',),
        ('0.1.0-gamma.1',),
        ('0.1.0-RC.1',),
    ]
)
def test_invalid_version(version: str) -> None:
    criteria = VALID_CRITERIA | dict(version=version)
    with pytest.raises(ValidationError) as e:
        Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]

    errors = e.value.errors()
    assert errors[0]['msg'] == _invalid_version_msg


@pytest.mark.parametrize(
    ['version'],
    [
        ('1.0.0',),
        ('1.2.3',),
        ('1.22222.30000',),
        ('1.2.3-alpha.1',),
        ('1.2.3-alpha.2',),
        ('1.2.3-rc.2',),
        ('1.2.3-beta.2',),
        ('1.2.3-alpha.299',),
    ]
)
def test_valid_version(version: str) -> None:
    criteria = VALID_CRITERIA | dict(version=version)
    Criteria(**criteria).to_validated(evaluation_interval=1000, max_signal_bits=2)  # type: ignore[arg-type]
