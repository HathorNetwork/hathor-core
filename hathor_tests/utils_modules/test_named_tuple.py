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
from hathor.utils.pydantic import BaseModel


class InnerTuple(NamedTuple):
    x: str


class InnerModel(BaseModel):
    y: str


class OuterTuple(NamedTuple):
    a: int
    b: InnerTuple
    c: InnerModel

    @classmethod
    def validate_a(cls, a: int) -> int:
        if a > 10:
            raise ValueError('"a" cannot be greater than 10')

        return a


VALIDATORS = dict(
    validate_a=pydantic.validator('a')(OuterTuple.validate_a)
)


@pytest.mark.parametrize(
    ['attributes', 'expected'],
    [
        (
            dict(a=0, b=('b',), c=dict(y='c')),
            OuterTuple(a=0, b=InnerTuple(x='b'), c=InnerModel(y='c'))
        ),
        (
            dict(a=5, b=('bb',), c=dict(y='cc')),
            OuterTuple(a=5, b=InnerTuple(x='bb'), c=InnerModel(y='cc'))
        ),
        (
            dict(a=10, b=('bbb',), c=dict(y='ccc')),
            OuterTuple(a=10, b=InnerTuple(x='bbb'), c=InnerModel(y='ccc'))
        ),
    ]
)
def test_validated_named_tuple_from_dict(attributes, expected):
    result = validated_named_tuple_from_dict(OuterTuple, attributes, validators=VALIDATORS)

    assert isinstance(result.b, InnerTuple)
    assert isinstance(result.c, InnerModel)
    assert result == expected


@pytest.mark.parametrize(
    'attributes',
    [
        dict(a=11, b=('b',), c=dict(y='c')),
        dict(a=50, b=('bb',), c=dict(y='cc')),
        dict(a=100, b=('bbb',), c=dict(y='ccc')),
    ]
)
def test_validated_named_tuple_from_dict_error(attributes):
    with pytest.raises(ValidationError) as e:
        validated_named_tuple_from_dict(OuterTuple, attributes, validators=VALIDATORS)

    errors = e.value.errors()
    assert errors[0]['msg'] == '"a" cannot be greater than 10'
