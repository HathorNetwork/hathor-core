#  Copyright 2025 Hathor Labs
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

from __future__ import annotations

from types import NoneType, UnionType
# XXX: ignore attr-defined because mypy doesn't recognize it, even though all version of python that we support; have
#      this defined, even if it's an internal class
from typing import TypeVar, _UnionGenericAlias as UnionGenericAlias, get_args  # type: ignore[attr-defined]

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.optional import decode_optional, encode_optional

V = TypeVar('V')


class OptionalNCType(NCType[V | None]):
    """ Represents a nc_type that is either `V` or `None`.
    """

    __slots__ = ('_is_hashable', '_value')

    _value: NCType[V]

    def __init__(self, nc_type: NCType[V]) -> None:
        self._value = nc_type
        self._is_hashable = nc_type.is_hashable()

    @override
    @classmethod
    def _from_type(cls, type_: type[V | None], /, *, type_map: NCType.TypeMap) -> Self:
        if not isinstance(type_, (UnionType, UnionGenericAlias)):
            raise TypeError('expected type union')
        args = get_args(type_)
        assert args, 'union always has args'
        if len(args) != 2 or NoneType not in args:
            raise TypeError('type must be either `None | T` or `T | None`')
        not_none_type, = tuple(set(args) - {NoneType})  # get the type that is not None
        return cls(NCType.from_type(not_none_type, type_map=type_map))

    @override
    def _check_value(self, value: V | None, /, *, deep: bool) -> None:
        if value is None:
            return
        if deep:
            self._value._check_value(value, deep=True)

    @override
    def _serialize(self, serializer: Serializer, value: V | None, /) -> None:
        encode_optional(serializer, value, self._value.serialize)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> V | None:
        return decode_optional(deserializer, self._value.deserialize)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> V | None:
        if json_value is None:
            return None
        else:
            return self._value.json_to_value(json_value)

    @override
    def _value_to_json(self, value: V | None, /) -> NCType.Json:
        if value is None:
            return None
        else:
            return self._value.value_to_json(value)
