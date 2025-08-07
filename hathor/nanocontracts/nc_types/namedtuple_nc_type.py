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

from collections.abc import Iterable
from typing import NamedTuple, TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer

N = TypeVar('N', bound=tuple)


# XXX: we can't usefully describe the tuple type
class NamedTupleNCType(NCType[N]):
    __slots__ = ('_is_hashable', '_args', '_actual_type')

    # we can't even parametrize NCType, lists are allowed in tuples and it's still hashable it just fails in runtime
    _args: tuple[NCType, ...]
    _actual_type: type[N]

    def __init__(self, namedtuple: type[N], args: Iterable[NCType]) -> None:
        self._actual_type = namedtuple
        self._args = tuple(args)
        self._is_hashable = all(arg_nc_type.is_hashable() for arg_nc_type in self._args)

    @override
    @classmethod
    def _from_type(cls, type_: type[N], /, *, type_map: NCType.TypeMap) -> Self:
        if not issubclass(type_, tuple) and NamedTuple not in getattr(cls, '__orig_bases__', tuple()):
            raise TypeError('expected NamedTuple type')
        args = [type_.__annotations__[field_name] for field_name in type_._fields]  # type: ignore[attr-defined]
        return cls(type_, (NCType.from_type(arg, type_map=type_map) for arg in args))

    @override
    def _check_value(self, value: N, /, *, deep: bool) -> None:
        if not isinstance(value, (tuple, self._actual_type)):
            raise TypeError('expected tuple or namedtuple')
        # TODO: support default values
        if len(value) != len(self._args):
            raise TypeError('wrong number of arguments')
        if deep:
            for i, arg_nc_type in zip(value, self._args):
                arg_nc_type._check_value(i, deep=True)

    @override
    def _serialize(self, serializer: Serializer, value: N, /) -> None:
        from hathor.serialization.compound_encoding.tuple import encode_tuple
        encode_tuple(serializer, value, tuple(i.serialize for i in self._args))

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> N:
        from hathor.serialization.compound_encoding.tuple import decode_tuple
        return self._actual_type(*decode_tuple(deserializer, tuple(i.deserialize for i in self._args)))

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> N:
        if not isinstance(json_value, list):
            raise ValueError('expected list')
        return self._actual_type(*tuple(v.json_to_value(i) for (i, v) in zip(json_value, self._args)))

    @override
    def _value_to_json(self, value: N) -> NCType.Json:
        return [v.value_to_json(i) for (i, v) in zip(value, self._args)]
