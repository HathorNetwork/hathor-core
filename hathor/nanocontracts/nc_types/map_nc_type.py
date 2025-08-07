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

from abc import ABC, abstractmethod
from collections.abc import Hashable, Mapping
from typing import Iterable, TypeVar, get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.nc_types.utils import is_origin_hashable
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.mapping import decode_mapping, encode_mapping

T = TypeVar('T')
H = TypeVar('H', bound=Hashable)


class _MapNCType(NCType[Mapping[H, T]], ABC):
    """ Base class to help implement NCType for mappings.
    """

    __slots__ = ('_key', '_value')

    _key: NCType[H]
    _value: NCType[T]
    _is_hashable = False

    def __init__(self, key: NCType[H], value: NCType[T]) -> None:
        self._key = key
        self._value = value

    @abstractmethod
    def _build(self, items: Iterable[tuple[H, T]]) -> Mapping[H, T]:
        """ How to build the concrete map from an iterable of (key, value).
        """
        raise NotImplementedError

    @override
    @classmethod
    def _from_type(cls, type_: type[Mapping[H, T]], /, *, type_map: NCType.TypeMap) -> Self:
        origin_type: type = get_origin(type_) or type_
        if not issubclass(origin_type, Mapping):
            raise TypeError('expected Mapping type')
        args = get_args(type_)
        if not args or len(args) != 2:
            raise TypeError(f'expected {type_.__name__}[<key type>, <value type>]')
        key_type, value_type = args
        if not is_origin_hashable(key_type):
            raise TypeError(f'{key_type} is not hashable')
        key_nc_type = NCType.from_type(key_type, type_map=type_map)
        assert key_nc_type.is_hashable(), 'hashable "types" must produce hashable "values"'
        return cls(key_nc_type, NCType.from_type(value_type, type_map=type_map))

    @override
    def _check_value(self, value: Mapping[H, T], /, *, deep: bool) -> None:
        if not isinstance(value, Mapping):
            raise TypeError('expected Mapping type')
        if deep:
            for k, v in value.items():
                self._key._check_value(k, deep=True)
                self._value._check_value(v, deep=True)

    @override
    def _serialize(self, serializer: Serializer, value: Mapping[H, T], /) -> None:
        encode_mapping(serializer, value, self._key.serialize, self._value.serialize)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> Mapping[H, T]:
        return decode_mapping(
            deserializer,
            self._key.deserialize,
            self._value.deserialize,
            self._build,
        )

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> Mapping[H, T]:
        if not isinstance(json_value, dict):
            raise ValueError('expected dict')
        return self._build((self._key.json_to_value(k), self._value.json_to_value(v)) for k, v in json_value.items())

    @override
    def _value_to_json(self, value: Mapping[H, T], /) -> NCType.Json:
        return {self._key.value_to_json(k): self._value.value_to_json(v) for k, v in value.items()}


class DictNCType(_MapNCType):
    """ Represents builtin `dict` values.
    """

    @override
    def _build(self, items: Iterable[tuple[H, T]]) -> dict[H, T]:
        return dict(items)
