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

from typing import NamedTuple

import pydantic
import pytest
from pydantic import ValidationError

from hathor.utils.named_tuple import validated_named_tuple_from_dict


class TestTuple(NamedTuple):
    a: int
    b: int
    c: str

    @classmethod
    def validate_b(cls, b: int) -> int:
        if b > 10:
            raise ValueError('b cannot be greater than 10')

        return b


VALIDATORS = dict(
    validate_b=pydantic.validator('b')(TestTuple.validate_b)
)


@pytest.mark.parametrize(
    ['attributes', 'expected'],
    [
        (dict(a=1, b=0, c='a'), TestTuple(1, 0, 'a')),
        (dict(a=123, b=5, c='aa'), TestTuple(123, 5, 'aa')),
        (dict(a=1010, b=10, c='aaa'), TestTuple(1010, 10, 'aaa')),
    ]
)
def test_validated_named_tuple_from_dict(attributes, expected):
    result = validated_named_tuple_from_dict(TestTuple, attributes, validators=VALIDATORS)

    assert result == expected


@pytest.mark.parametrize(
    'attributes',
    [
        dict(a=1, b=11, c='a'),
        dict(a=123, b=50, c='aa'),
        dict(a=1010, b=100, c='aaa'),
    ]
)
def test_validated_named_tuple_from_dict_error(attributes):
    with pytest.raises(ValidationError) as e:
        validated_named_tuple_from_dict(TestTuple, attributes, validators=VALIDATORS)

    errors = e.value.errors()
    assert errors[0]['msg'] == 'b cannot be greater than 10'
