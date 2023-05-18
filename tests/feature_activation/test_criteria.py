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

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from hathor.feature_activation.model.criteria import Criteria

VALID_CRITERIA = dict(
    bit=0,
    start_height=1000,
    timeout_height=2000,
    threshold=0,
    minimum_activation_height=0,
    activate_on_timeout=False,
    version='0.0.0'
)


@patch('hathor.feature_activation.model.criteria.Criteria.evaluation_interval', 1000)
@patch('hathor.feature_activation.model.criteria.Criteria.max_signal_bits', 2)
class TestCriteria:
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
                activate_on_timeout=True,
                version='0.52.3'
            )
        ]
    )
    def test_valid_criteria(self, criteria):
        Criteria(**criteria)

    @pytest.mark.parametrize(
        ['bit', 'error'],
        [
            (-10, 'ensure this value is greater than or equal to 0'),
            (-1, 'ensure this value is greater than or equal to 0'),
            (2, 'bit must be lower than max_signal_bits: 2 >= 2'),
            (10, 'bit must be lower than max_signal_bits: 10 >= 2')
        ]
    )
    def test_bit(self, bit, error):
        criteria = VALID_CRITERIA | dict(bit=bit)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

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
    def test_start_height(self, start_height, error):
        criteria = VALID_CRITERIA | dict(start_height=start_height)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

        errors = e.value.errors()
        assert errors[0]['msg'] == error

    @pytest.mark.parametrize(
        ['timeout_height', 'error'],
        [
            (-10, 'ensure this value is greater than or equal to 0'),
            (-1, 'ensure this value is greater than or equal to 0'),
            (1, 'timeout_height must be greater than start_height: 1 <= 1000'),
            (45, 'timeout_height must be greater than start_height: 45 <= 1000'),
            (100, 'timeout_height must be greater than start_height: 100 <= 1000'),
            (1111, 'Should be a multiple of evaluation_interval: 1111 % 1000 != 0')
        ]
    )
    def test_timeout_height(self, timeout_height, error):
        criteria = VALID_CRITERIA | dict(timeout_height=timeout_height)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

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
    def test_threshold(self, threshold, error):
        criteria = VALID_CRITERIA | dict(threshold=threshold)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

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
            (10_000, 'minimum_activation_height must not be greater than timeout_height: 10000 > 2000')
        ]
    )
    def test_minimum_activation_height(self, minimum_activation_height, error):
        criteria = VALID_CRITERIA | dict(minimum_activation_height=minimum_activation_height)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

        errors = e.value.errors()
        assert errors[0]['msg'] == error

    @pytest.mark.parametrize(
        ['version', 'error'],
        [
            ('0', 'string does not match regex "^(\\d+\\.\\d+\\.\\d+(-rc\\.\\d+)?|nightly-[a-f0-9]{7,8})$"'),
            ('alpha', 'string does not match regex "^(\\d+\\.\\d+\\.\\d+(-rc\\.\\d+)?|nightly-[a-f0-9]{7,8})$"'),
            ('0.0', 'string does not match regex "^(\\d+\\.\\d+\\.\\d+(-rc\\.\\d+)?|nightly-[a-f0-9]{7,8})$"')
        ]
    )
    def test_version(self, version, error):
        criteria = VALID_CRITERIA | dict(version=version)
        with pytest.raises(ValidationError) as e:
            Criteria(**criteria)

        errors = e.value.errors()
        assert errors[0]['msg'] == error
