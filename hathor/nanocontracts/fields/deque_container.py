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

from collections import deque
from collections.abc import Container as ContainerAbc, Iterable, Iterator, Sequence, Sized
from dataclasses import dataclass, replace
from typing import ClassVar, SupportsIndex, TypeVar, get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.blueprint_env import NCAttrCache
from hathor.nanocontracts.fields.container import KEY_SEPARATOR, Container, ContainerNode, ContainerNodeFactory
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import VarInt32NCType
from hathor.nanocontracts.nc_types.dataclass_nc_type import make_dataclass_nc_type
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none

T = TypeVar('T')
_METADATA_KEY: bytes = b'__metadata__'
_INDEX_NC_TYPE = VarInt32NCType()

# TODO: support maxlen (will require support for initialization values)


@dataclass(slots=True, frozen=True, kw_only=True)
class _DequeMetadata:
    first_index: int = 0
    length: int = 0
    reversed: bool = False

    @property
    def last_index(self) -> int:
        return self.first_index + self.length - 1


_METADATA_NC_TYPE = make_dataclass_nc_type(_DequeMetadata)


class DequeContainer(Container[T]):
    # from https://github.com/python/typeshed/blob/main/stdlib/collections/__init__.pyi
    __slots__ = ('__storage__', '__prefix__', '__value_node', '__metadata_key')
    __value_node: ContainerNode[T]
    __metadata_key: bytes

    def __init__(self, storage: NCContractStorage, prefix: bytes, value_node: ContainerNode[T]) -> None:
        self.__storage__ = storage
        self.__prefix__ = prefix
        self.__value_node = value_node
        self.__metadata_key = KEY_SEPARATOR.join([self.__prefix__, _METADATA_KEY])

    # Methods needed by Container:

    @override
    @classmethod
    def __check_type__(cls, type_: type[ContainerAbc[T]], type_map: Field.TypeMap) -> None:
        origin_type: type[ContainerAbc[T]] = not_none(get_origin(type_))
        if not issubclass(origin_type, Sequence):
            raise TypeError('expected Sequence type')
        args = get_args(type_)
        if not args or len(args) != 1:
            raise TypeError('expected exactly 1 type argument')
        value_type, = args
        _ = ContainerNodeFactory.check_is_container(value_type, type_map)

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
    ) -> 'Self':
        item_type, = get_args(type_)
        item_node = ContainerNode.from_type(storage, item_type, cache=cache, type_map=type_map)
        return cls(storage, prefix, item_node)

    @override
    def __init_storage__(self, initial_value: ContainerAbc[T] | None = None) -> None:
        self.__storage__.put_obj(self.__metadata_key, _METADATA_NC_TYPE, _DequeMetadata())
        if initial_value is not None:
            if not isinstance(initial_value, Sequence):
                raise TypeError('expected initial_value to be a Sequence')
            self.extend(initial_value)

    # INTERNAL METHODS: all of these must be __dunder_methods so they aren't accessible from an OCB

    def __to_db_key(self, index: SupportsIndex) -> bytes:
        return KEY_SEPARATOR.join([self.__prefix__, _INDEX_NC_TYPE.to_bytes(index.__index__())])

    def __get_metadata(self) -> _DequeMetadata:
        metadata = self.__storage__.get_obj(self.__metadata_key, _METADATA_NC_TYPE)
        return metadata

    def __update_metadata(self, new_metadata: _DequeMetadata) -> None:
        self.__storage__.put_obj(self.__metadata_key, _METADATA_NC_TYPE, new_metadata)

    def __extend(self, *, items: Iterable[T], metadata: _DequeMetadata) -> None:
        new_last_index = metadata.last_index
        for item in items:
            new_last_index += 1
            db_key = self.__to_db_key(new_last_index)
            self.__value_node.set_value(db_key, item)
        new_metadata = replace(metadata, length=new_last_index - metadata.first_index + 1)
        self.__update_metadata(new_metadata)

    def __extendleft(self, *, items: Iterable[T], metadata: _DequeMetadata) -> None:
        new_first_index = metadata.first_index
        for item in items:
            new_first_index -= 1
            db_key = self.__to_db_key(new_first_index)
            self.__value_node.set_value(db_key, item)
        new_metadata = replace(
            metadata,
            first_index=new_first_index,
            length=metadata.last_index - new_first_index + 1,
        )
        self.__update_metadata(new_metadata)

    def __pop(self, *, metadata: _DequeMetadata, left: bool) -> T:
        if metadata.length == 0:
            raise IndexError

        index = metadata.first_index if left else metadata.last_index
        db_key = self.__to_db_key(index)
        item = self.__value_node.get_value(db_key)
        self.__value_node.del_value(db_key)
        new_metadata = replace(
            metadata,
            first_index=metadata.first_index + 1 if left else metadata.first_index,
            length=metadata.length - 1
        )
        self.__update_metadata(new_metadata)
        return item

    def __to_internal_index(self, *, index: SupportsIndex) -> int:
        metadata = self.__get_metadata()
        idx = index.__index__()

        if idx < 0:
            idx += metadata.length

        if idx < 0 or idx >= metadata.length:
            raise IndexError

        return metadata.last_index - idx if metadata.reversed else metadata.first_index + idx

    # Methods needed by MutableSequence and Sequence:

    def __getitem__(self, index: SupportsIndex, /) -> T:
        internal_index = self.__to_internal_index(index=index)
        db_key = self.__to_db_key(internal_index)
        try:
            return self.__value_node.get_value(db_key)
        except KeyError:
            raise KeyError(index)

    def __len__(self) -> int:
        return self.__get_metadata().length

    def __setitem__(self, index: SupportsIndex, item: T, /) -> None:
        internal_index = self.__to_internal_index(index=index)
        db_key = self.__to_db_key(internal_index)
        self.__value_node.set_value(db_key, item)

    def __delitem__(self, key: SupportsIndex, /) -> None:
        raise NotImplementedError

    def insert(self, i: int, x: T, /) -> None:
        raise NotImplementedError

    # Methods provided by Sequence (currently not implemented):

    # def index(self, x: T, start: int = 0, stop: int = ..., /) -> int: ...
    # def count(self, x: T, /) -> int: ...
    # def __contains__(self, key: object, /) -> bool: ...
    # def __iter__(self) -> Iterator[_T_co]: ...
    # def __reversed__(self) -> None:

    # Methods provided by MutableSequence (currently not implemented):

    # def append(self, x: T, /) -> None: ...
    # def clear(self) -> None: ...
    # def extend(self, iterable: Iterable[T], /) -> None: ...
    # def reverse(self) -> None:
    # def pop(self) -> T: ...  # type: ignore[override]
    # def remove(self, value: T, /) -> None: ...
    # def __iadd__(self, value: Iterable[T], /) -> Self: ...

    # out of those, we specialize these:

    def append(self, item: T, /) -> None:
        self.extend((item,))

    def extend(self, items: Iterable[T], /) -> None:
        metadata = self.__get_metadata()
        if metadata.reversed:
            return self.__extendleft(items=items, metadata=metadata)
        self.__extend(items=items, metadata=metadata)

    def pop(self) -> T:
        metadata = self.__get_metadata()
        return self.__pop(metadata=metadata, left=metadata.reversed)

    def reverse(self) -> None:
        metadata = self.__get_metadata()
        new_metadata = replace(metadata, reversed=not metadata.reversed)
        self.__update_metadata(new_metadata)

    def __iter__(self) -> Iterator[T]:
        metadata = self.__get_metadata()
        indexes = range(metadata.first_index, metadata.last_index + 1)

        if metadata.reversed:
            indexes = range(metadata.last_index, metadata.first_index - 1, -1)

        for i in indexes:
            db_key = self.__to_db_key(i)
            yield self.__value_node.get_value(db_key)

    # Other deque methods that we implement to look like a deque:

    @property
    def maxlen(self) -> int | None:
        return None

    def appendleft(self, item: T, /) -> None:
        self.extendleft((item,))

    def extendleft(self, items: Iterable[T], /) -> None:
        metadata = self.__get_metadata()
        if metadata.reversed:
            return self.__extend(items=items, metadata=metadata)
        self.__extendleft(items=items, metadata=metadata)

    def popleft(self) -> T:
        metadata = self.__get_metadata()
        return self.__pop(metadata=metadata, left=not metadata.reversed)

    def copy(self) -> 'Self':
        raise NotImplementedError

    def rotate(self, n: int = 1, /) -> None:
        raise NotImplementedError

    def __copy__(self) -> 'Self':
        raise NotImplementedError

    __hash__: ClassVar[None]  # type: ignore[assignment]

    def __reduce__(self) -> tuple[type['Self'], tuple[()], None, Iterator[T]]:
        raise NotImplementedError

    def __add__(self, value: 'Self', /) -> 'Self':
        raise NotImplementedError

    def __mul__(self, value: int, /) -> 'Self':
        raise NotImplementedError

    def __imul__(self, value: int, /) -> 'Self':
        raise NotImplementedError

    def __lt__(self, value: deque[T], /) -> bool:
        raise NotImplementedError

    def __le__(self, value: deque[T], /) -> bool:
        raise NotImplementedError

    def __gt__(self, value: deque[T], /) -> bool:
        raise NotImplementedError

    def __ge__(self, value: deque[T], /) -> bool:
        raise NotImplementedError

    def __eq__(self, value: object, /) -> bool:
        # XXX: return True if they point to the same data
        if isinstance(value, DequeContainer) and self.__prefix__ == value.__prefix__:
            return True
        if isinstance(value, Iterable) and isinstance(value, Sized):
            if len(value) != len(self):
                return False
            for i, j in zip(value, self):
                if i != j:
                    return False
            return True
        else:
            raise TypeError(f'cannot compare with value of type {type(value)}')
