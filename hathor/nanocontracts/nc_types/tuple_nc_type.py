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
from typing import get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer


# XXX: we can't usefully describe the tuple type
class TupleNCType(NCType[tuple]):
    """ Represents tuple values, which can either be homogeneous-type variable size or heterogeneous-type fixed size.
    """

    __slots__ = ('_is_hashable', '_varsize', '_args')

    _varsize: bool
    # we can't even parametrize NCType, lists are allowed in tuples and it's still hashable it just fails in runtime
    _args: tuple[NCType, ...]

    def __init__(self, args: NCType | Iterable[NCType]) -> None:
        if isinstance(args, Iterable):
            self._varsize = False
            self._args = tuple(args)
            for arg in self._args:
                assert isinstance(arg, NCType)
            self._is_hashable = all(arg_nc_type.is_hashable() for arg_nc_type in self._args)
        else:
            assert isinstance(args, NCType)
            self._varsize = True
            self._args = (args,)
            self._is_hashable = args.is_hashable()

    @override
    @classmethod
    def _from_type(cls, type_: type[tuple], /, *, type_map: NCType.TypeMap) -> Self:
        origin_type: type = get_origin(type_) or type_
        if not issubclass(origin_type, (tuple, list)):
            raise TypeError('expected tuple-like type')
        args = list(get_args(type_))
        if args is None:
            raise TypeError('expected tuple[<args...>]')
        if issubclass(origin_type, list):
            args.append(Ellipsis)
        if args and args[-1] == Ellipsis:
            if len(args) != 2:
                raise TypeError('ellipsis only allowed with one type: tuple[T, ...]')
            arg, _ellipsis = args
            return cls(NCType.from_type(arg, type_map=type_map))
        else:
            return cls(NCType.from_type(arg, type_map=type_map) for arg in args)

    @override
    def _check_value(self, value: tuple, /, *, deep: bool) -> None:
        if not isinstance(value, (tuple, list)):
            raise TypeError('expected tuple-like')
        if deep:
            if self._varsize:
                arg_nc_type, = self._args
                for i in value:
                    arg_nc_type._check_value(i, deep=True)
            else:
                if len(value) != len(self._args):
                    raise TypeError('wrong tuple size')
                for i, arg_nc_type in zip(value, self._args):
                    arg_nc_type._check_value(i, deep=True)

    @override
    def _serialize(self, serializer: Serializer, value: tuple, /) -> None:
        from hathor.serialization.compound_encoding.collection import encode_collection
        from hathor.serialization.compound_encoding.tuple import encode_tuple
        if self._varsize:
            assert len(self._args) == 1
            encode_collection(serializer, value, self._args[0].serialize)
        else:
            encode_tuple(serializer, value, tuple(i.serialize for i in self._args))

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> tuple:
        from hathor.serialization.compound_encoding.collection import decode_collection
        from hathor.serialization.compound_encoding.tuple import decode_tuple
        if self._varsize:
            assert len(self._args) == 1
            return decode_collection(deserializer, self._args[0].deserialize, tuple)
        else:
            return decode_tuple(deserializer, tuple(i.deserialize for i in self._args))

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> tuple:
        if not isinstance(json_value, list):
            raise ValueError('expected list')
        if self._varsize:
            assert len(self._args) == 1
            return tuple(self._args[0].json_to_value(i) for i in json_value)
        else:
            return tuple(v.json_to_value(i) for (i, v) in zip(json_value, self._args))

    @override
    def _value_to_json(self, value: tuple, /) -> NCType.Json:
        if self._varsize:
            assert len(self._args) == 1
            return [self._args[0].value_to_json(i) for i in value]
        else:
            return [v.value_to_json(i) for (i, v) in zip(value, self._args)]
