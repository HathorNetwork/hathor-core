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
from collections import deque
from collections.abc import Collection, Hashable, Iterable, Set
from typing import TypeVar, get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.nc_types.utils import is_origin_hashable
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.collection import decode_collection, encode_collection

T = TypeVar('T')
H = TypeVar('H', bound=Hashable)


class _CollectionNCType(NCType[Collection[T]], ABC):
    """ Used as base for NCType classes that represent collecions.
    """
    __slots__ = ('_item',)

    _is_hashable = False
    _item: NCType[T]

    def __init__(self, item_nc_type: NCType[T], /) -> None:
        self._item = item_nc_type

    @abstractmethod
    def _build(self, items: Iterable[T]) -> Collection[T]:
        """ How to build the concrete collection from an iterable of items.
        """
        raise NotImplementedError

    @override
    @classmethod
    def _from_type(cls, type_: type[Collection[T]], /, *, type_map: NCType.TypeMap) -> Self:
        member_type = cls._get_member_type(type_)
        member_nc_type = NCType.from_type(member_type, type_map=type_map)
        return cls(member_nc_type)

    @classmethod
    def _get_member_type(cls, type_: type[Collection[T]]) -> type[T]:
        origin_type: type = get_origin(type_) or type_
        if not issubclass(origin_type, Collection):
            raise TypeError('expected Collection type')
        args = get_args(type_)
        if not args or len(args) != 1:
            raise TypeError(f'expected {type_.__name__}[<type>]')
        return args[0]

    def _check_item(self, item: T) -> None:
        self._item._check_value(item, deep=True)

    @override
    def _check_value(self, value: Collection[T], /, *, deep: bool) -> None:
        if not isinstance(value, Collection):
            raise TypeError('expected Collection type')
        if deep:
            for i in value:
                self._check_item(i)

    @override
    def _serialize(self, serializer: Serializer, value: Collection[T], /) -> None:
        encode_collection(serializer, value, self._item.serialize)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> Collection[T]:
        return decode_collection(
            deserializer,
            self._item.deserialize,
            self._build,
        )

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> Collection[T]:
        if not isinstance(json_value, list):
            raise ValueError('expected list')
        return self._build(self._item.json_to_value(i) for i in json_value)

    @override
    def _value_to_json(self, value: Collection[T], /) -> NCType.Json:
        return [self._item.value_to_json(i) for i in value]


class ListNCType(_CollectionNCType[T]):
    """ Represents builtin `list` values.
    """

    @override
    def _build(self, items: Iterable[T]) -> list[T]:
        return list(items)


class DequeNCType(_CollectionNCType[T]):
    """ Represents builtin `collections.deque` values.
    """

    @override
    def _build(self, items: Iterable[T]) -> deque[T]:
        return deque(items)


class SetNCType(_CollectionNCType[H]):
    """ Represents builtin `set` values.
    """

    @override
    def _build(self, items: Iterable[H]) -> Set[H]:
        return set(items)

    @override
    @classmethod
    def _get_member_type(cls, type_: type[Collection[T]]) -> type[T]:
        origin_type: type = get_origin(type_) or type_
        if not issubclass(origin_type, Set):
            raise TypeError('expected Set type')
        args = get_args(type_)
        if not args or len(args) != 1:
            raise TypeError(f'expected {type_.__name__}[<type>]')
        member_type, = args
        if not is_origin_hashable(args[0]):
            raise TypeError(f'{args[0]} is not hashable')
        return member_type

    @override
    def _check_item(self, item: H) -> None:
        if not isinstance(item, Hashable):
            raise TypeError('expected Hashable type')
        super()._check_item(item)


class FrozenSetNCType(SetNCType[H]):
    """ Represents builtin `frozenset` values.
    """

    # XXX: SetNCType already enforces H to be hashable, but is not itself hashable, a frozenset, however, is hashable
    _is_hashable = True

    @override
    def _build(self, items: Iterable[H]) -> frozenset[H]:
        return frozenset(items)
