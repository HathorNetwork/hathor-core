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

from typing import Any, NamedTuple, TypeVar, get_type_hints

from pydantic import TypeAdapter, create_model

from hathor.utils.pydantic import BaseModel

T = TypeVar('T', bound=NamedTuple)


def validated_named_tuple_from_dict(
    named_tuple_type: type[T],
    attributes_dict: dict[str, Any],
    *,
    validators: dict[str, Any] | None = None
) -> T:
    """
    Takes an attributes dict and returns a validated instance of the specified NamedTuple subclass.
    Performs validation using pydantic.

    Args:
        named_tuple_type: the NamedTuple subclass to create an instance from
        attributes_dict: a dict with all required attributes for the NamedTuple subclass
        validators: custom pydantic field_validators (dict of name -> decorated validator)

    Returns: a validated instance of the specified NamedTuple subclass
    """
    if not validators:
        # Simple case: use TypeAdapter directly (Pydantic v2 native NamedTuple support)
        adapter = TypeAdapter(named_tuple_type)
        return adapter.validate_python(attributes_dict)

    # Complex case with validators: create a dynamic model
    type_hints = get_type_hints(named_tuple_type)
    defaults = getattr(named_tuple_type, '_field_defaults', {})

    field_definitions: dict[str, Any] = {
        name: (hint, defaults.get(name, ...))
        for name, hint in type_hints.items()
    }

    model = create_model(
        f'{named_tuple_type.__name__}Model',
        __base__=BaseModel,
        __validators__=validators,
        **field_definitions
    )

    # Fill in defaults via intermediate NamedTuple, then validate
    all_attributes = named_tuple_type(**attributes_dict)  # type: ignore[call-overload]
    validated = model.model_validate(all_attributes._asdict())

    # Use dict comprehension to get validated attributes directly from the model
    # instead of model_dump() which would convert nested Pydantic models to dicts
    validated_dict = {name: getattr(validated, name) for name in type_hints}
    return named_tuple_type(**validated_dict)  # type: ignore[call-overload]
