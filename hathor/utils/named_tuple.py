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

from typing import Any, NamedTuple, Optional, TypeVar

import pydantic

from hathor.utils.pydantic import BaseModel

T = TypeVar('T', bound=NamedTuple)


def validated_named_tuple_from_dict(
    named_tuple_type: type[T],
    attributes_dict: dict[str, Any],
    *,
    validators: Optional[dict[str, classmethod]] = None
) -> T:
    """
    Takes an attributes dict and returns a validated instance of the specified NamedTuple subclass.
    Performs validation using pydantic.

    Args:
        named_tuple_type: the NamedTuple subclass to create an instance from
        attributes_dict: a dict with all required attributes for the NamedTuple subclass
        validators: custom pydantic validators (read https://docs.pydantic.dev/latest/usage/validators)

    Returns: a validated instance of the specified NamedTuple subclass
    """
    model = pydantic.create_model_from_namedtuple(
        named_tuple_type,
        __base__=BaseModel,
        __validators__=validators
    )

    # This intermediate step shouldn't be necessary, but for some reason pydantic.create_model_from_namedtuple
    # doesn't support default attribute values, so we do this to add them
    all_attributes = named_tuple_type(**attributes_dict)
    validated_attributes = model(**all_attributes._asdict())
    validated_attributes_dict = {k: v for k, v in validated_attributes}

    return named_tuple_type(**validated_attributes_dict)
