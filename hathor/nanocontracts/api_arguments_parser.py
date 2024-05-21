# Copyright 2023 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import inspect
import json
from types import GenericAlias
from typing import Any, NamedTuple, Optional, Type, TypeVar, Union, get_args, get_origin

from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCMethodNotFound
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import SignedData

# This is a workaround, so mypy doesn't complain about Optional type checking
# The optional fields comes as _UnionGenericAlias and this helps us, so we don't
# need to use any private variable
X = TypeVar('X')
UnionGenericAlias = type(Optional[X])


def get_supertype(_type: Type) -> Type:
    """Return the supertype of a NewType. If it's not a NewType, return the same type.
    """
    if hasattr(_type, '__supertype__'):
        return _type.__supertype__
    return _type


def parse_nc_method_call(blueprint_class: Type[Blueprint], call_info: str) -> tuple[str, Any]:
    """Parse a string that represents an invocation to a Nano Contract method.

    The string must be in the following format: `method(arg1, arg2, arg3)`.

    The arguments must be in JSON format; tuples and namedtuples should be replaced by a list.

    Here are some examples:
    - add(1, 2)
    - set_result("1x2")
    """
    if not call_info.endswith(')'):
        raise ValueError

    method_name, _, arguments = call_info[:-1].partition('(')
    method = getattr(blueprint_class, method_name, None)
    if method is None:
        raise NCMethodNotFound(f'{blueprint_class.__name__}.{method_name}')

    parser = NCMethodParser(method)
    method_args = parser.get_method_args()

    args_array = json.loads(f'[{arguments}]')
    assert len(args_array) == len(method_args), f'{len(args_array)} != {len(method_args)} ({method_args})'

    parsed_args = []
    for (_, arg_type), arg_value in zip(method_args, args_array):
        parsed_args.append(parse_arg(arg_value, arg_type))

    return method_name, parsed_args


def is_subclass(type_: type, super_class: type) -> bool:
    """Reimplements issubclass() with support for recursive NewTypes."""
    if super_type := getattr(type_, '__supertype__', None):
        return is_subclass(super_type, super_class)
    return inspect.isclass(type_) and issubclass(type_, super_class)


def parse_arg(arg: Any, expected_type: Type) -> Any:
    """Return the parsed argument for a method call.
    This method is used when calling a private method in the state API

    If the argument must be bytes, we parse it from address or hex.

    We support int, float, str, bytes, address, list, tuple, namedtuple, and optional
    """
    if is_subclass(expected_type, bytes):
        # It can be an address, or it comes as an hexadecimal value
        if arg.startswith("a'") and arg.endswith("'"):
            # It's an address
            address = arg[2:-1]
            return decode_address(address)

        return bytes.fromhex(arg)

    if isinstance(expected_type, UnionGenericAlias):
        # All generic union here, we will handle only optional
        origin = get_origin(expected_type)
        type_args = get_args(expected_type)
        if origin == Union and type(None) in type_args:
            # Is optional
            # Optional types are Union of None and the expected type
            if arg is None:
                # The optional is actually None, so nothing to parse
                return arg

            optional_type = next(x for x in type_args if not isinstance(x, type(None)))
            return parse_arg(arg, optional_type)

    if isinstance(expected_type, GenericAlias):
        # List and tuple come as GenericAlias
        origin = get_origin(expected_type)
        type_args = get_args(expected_type)

        if origin == list:
            parsed_elements = []
            # We must call this same method recursively for each element of the iterator
            for element in arg:
                # List has a single type for all elements
                assert len(type_args) == 1
                parsed_elements.append(parse_arg(element, type_args[0]))

            return parsed_elements

        if origin == tuple:
            return handle_tuple_arg_parse(arg, type_args)

    # Handling NamedTuple
    if NamedTuple in getattr(expected_type, '__orig_bases__', []):
        named_tuple_types = list(expected_type.__annotations__.values())
        ret_tuple = handle_tuple_arg_parse(arg, named_tuple_types)
        return expected_type(*ret_tuple)

    # Handling custom nano field SignedData
    # we must get the origin because the SignedData field comes with
    # the data field as well, e.g., SignedData[str]
    origin = get_origin(expected_type)
    if origin == SignedData:
        # This gets the type of the data and must have only one element
        type_args = get_args(expected_type)
        assert len(type_args) == 1

        # The SignedData must be a list with two elements, where the first
        # is the data to sign, which depends on the type_args
        # and the second is the signature in hexadecimal
        assert len(arg) == 2

        signature = arg[1]
        arg = parse_arg(arg[0], type_args[0])

        return SignedData(arg, bytes.fromhex(signature))

    return arg


def handle_tuple_arg_parse(arg: Any, types: list[Type]) -> tuple:
    """Helper method to handle tuple parse."""
    parsed_elements = []
    # We must call this same method recursively for each element of the iterator
    for index, element in enumerate(arg):
        # Tuple has one type for each element
        parsed_elements.append(parse_arg(element, types[index]))

    return tuple(parsed_elements)
