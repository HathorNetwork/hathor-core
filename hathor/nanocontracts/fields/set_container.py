#  Copyright 2025 Hathor Labs
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

from collections.abc import Container as ContainerAbc, Iterable, Iterator
from typing import Any, TypeVar, get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.blueprint_env import NCAttrCache
from hathor.nanocontracts.fields.container import KEY_SEPARATOR, Container, ContainerLeaf
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import NCType, VarUint32NCType
from hathor.nanocontracts.nc_types.utils import is_origin_hashable
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none

T = TypeVar('T')
_S = TypeVar('_S')
_NOT_PROVIDED = object()
_LENGTH_KEY: bytes = b'__length__'
_LENGTH_NC_TYPE: NCType[int] = VarUint32NCType()


class SetContainer(Container[T]):
    # from https://github.com/python/typeshed/blob/main/stdlib/collections/__init__.pyi
    # from https://github.com/python/typeshed/blob/main/stdlib/typing.pyi

    __slots__ = ('__storage__', '__prefix__', '__member', '__length_key')
    __member: ContainerLeaf[T]
    __length_key: bytes

    # XXX: what to do with this:
    # __hash__: ClassVar[None]  # type: ignore[assignment]

    def __init__(self, storage: NCContractStorage, prefix: bytes, member: ContainerLeaf[T]) -> None:
        self.__storage__ = storage
        self.__prefix__ = prefix
        self.__member = member
        self.__length_key = KEY_SEPARATOR.join([self.__prefix__, _LENGTH_KEY])

    # Methods needed by Container:

    @override
    @classmethod
    def __check_type__(cls, type_: type[ContainerAbc[T]], type_map: Field.TypeMap) -> None:
        origin_type: type[ContainerAbc[T]] = not_none(get_origin(type_))
        if not issubclass(origin_type, set):
            raise TypeError('expected set type')
        args = get_args(type_)
        if not args or len(args) != 1:
            raise TypeError('expected exactly 1 type argument')
        item_type, = args
        if not is_origin_hashable(item_type):
            raise TypeError(f'{item_type} is not hashable')
        NCType.check_type(item_type, type_map=type_map.to_nc_type_map())

    @override
    @classmethod
    def __from_prefix_and_type__(
        cls,
        storage: NCContractStorage,
        prefix: bytes,
        type_: type[ContainerAbc[T]],
        /,
        *,
        cache: NCAttrCache,
        type_map: Field.TypeMap,
    ) -> Self:
        item_type, = get_args(type_)
        item_nc_type = NCType.from_type(item_type, type_map=type_map.to_nc_type_map())
        assert item_nc_type.is_hashable(), 'hashable "types" must produce hashable "values"'
        member_node = ContainerLeaf(storage, item_nc_type)
        return cls(storage, prefix, member_node)

    @override
    def __init_storage__(self, initial_value: ContainerAbc[T] | None = None) -> None:
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, 0)
        if initial_value is not None:
            if not isinstance(initial_value, set):
                raise TypeError('expected initial_value to be a set')
            self.update(initial_value)

    def __to_db_key(self, elem: T) -> bytes:
        # We don't need to explicitly hash the value here, because the trie already does it internally.
        return KEY_SEPARATOR.join([self.__prefix__, self.__member._nc_type.to_bytes(elem)])

    def __get_length(self) -> int:
        return self.__storage__.get_obj(self.__length_key, _LENGTH_NC_TYPE)

    def __increase_length(self) -> None:
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, self.__get_length() + 1)

    def __decrease_length(self) -> None:
        length = self.__get_length()
        assert length > 0
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, length - 1)

    # required by Iterable

    def __iter__(self) -> Iterator[T]:
        raise NotImplementedError

    # required bt Collection

    def __len__(self) -> int:
        return self.__get_length()

    # required by AbstractSet

    def __contains__(self, elem: T, /) -> bool:
        key = self.__to_db_key(elem)
        return self.__storage__.has_obj(key)

    # provided by Set (currently not implemented):
    #
    # def _hash(self) -> int: ...
    # def __le__(self, other: set[Any]) -> bool: ...
    # def __lt__(self, other: set[Any]) -> bool: ...
    # def __gt__(self, other: set[Any]) -> bool: ...
    # def __ge__(self, other: set[Any]) -> bool: ...
    # def __and__(self, other: set[Any]) -> set[T]: ...
    # def __or__(self, other: set[T]) -> set[T]: ...
    # def __sub__(self, other: set[Any]) -> set[T]: ...
    # def __xor__(self, other: set[T]) -> set[T]: ...
    # def __eq__(self, other: object) -> bool: ...
    # def isdisjoint(self, other: Iterable[Any]) -> bool: ...

    def isdisjoint(self, other: Iterable[Any]) -> bool:
        return len(self.intersection(other)) == 0

    # required by MutableSet

    def add(self, elem: T, /) -> None:
        key = self.__to_db_key(elem)
        if self.__member.has_value(key):
            return
        self.__member.set_value(key, elem)
        self.__increase_length()

    def discard(self, elem: T, /) -> None:
        key = self.__to_db_key(elem)
        if not self.__storage__.has_obj(key):
            return
        self.__storage__.del_obj(key)
        self.__decrease_length()

    # provided by MutableSet (currently not implemented):
    #
    # def clear(self) -> None: ...
    # def pop(self) -> T: ...
    # def remove(self, value: T) -> None: ...
    # def __ior__(self, it: set[T]) -> Self: ...  # type: ignore[override,misc]
    # def __iand__(self, it: set[Any]) -> Self: ...
    # def __ixor__(self, it: set[T]) -> Self: ...  # type: ignore[override,misc]
    # def __isub__(self, it: set[Any]) -> Self: ...

    # of which we override:

    def remove(self, elem: T, /) -> None:
        key = self.__to_db_key(elem)
        if not self.__member.has_value(key):
            raise KeyError
        self.__member.del_value(key)
        self.__decrease_length()

    # Additional methods to behave like a set
    # see https://github.com/python/typeshed/blob/main/stdlib/builtins.pyi#L1168

    def copy(self) -> set[T]:
        raise NotImplementedError

    def difference(self, *s: Iterable[Any]) -> set[T]:
        raise NotImplementedError

    def difference_update(self, *others: Iterable[Any]) -> None:
        for other in others:
            for elem in other:
                self.discard(elem)

    # def intersection(self, *s: Iterable[Any]) -> set[T]: ...
    def intersection(self, other: Iterable[Any]) -> set[T]:
        return set(elem for elem in other if elem in self)

    def intersection_update(self, *s: Iterable[Any]) -> None:
        raise NotImplementedError

    def issubset(self, s: Iterable[Any], /) -> bool:
        raise NotImplementedError

    def issuperset(self, other: Iterable[Any]) -> bool:
        return all(elem in self for elem in other)

    def symmetric_difference(self, s: Iterable[T], /) -> set[T]:
        raise NotImplementedError

    def symmetric_difference_update(self, s: Iterable[T], /) -> None:
        raise NotImplementedError

    def union(self, *s: Iterable[_S]) -> set[T | _S]:
        raise NotImplementedError

    def update(self, *others: Iterable[T]) -> None:
        for other in others:
            for elem in other:
                self.add(elem)
