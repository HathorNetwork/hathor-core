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
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, replace
from typing import ClassVar, SupportsIndex, TypeVar, get_args, get_origin

from typing_extensions import Self, override

from hathor.nanocontracts.exception import NCTypeError, NCIndexError
from hathor.nanocontracts.fields.container_field import KEY_SEPARATOR, ContainerField, StorageContainer
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import NCType, VarInt32NCType
from hathor.nanocontracts.nc_types.dataclass_nc_type import make_dataclass_opt_nc_type
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none

T = TypeVar('T')
_METADATA_KEY: str = '__metadata__'
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


_METADATA_NC_TYPE = make_dataclass_opt_nc_type(_DequeMetadata)


class DequeStorageContainer(StorageContainer[Sequence[T]]):
    # from https://github.com/python/typeshed/blob/main/stdlib/collections/__init__.pyi
    __slots__ = ('__storage', '__name', '__value', '__metadata_key')
    __storage: NCContractStorage
    __name: str
    __value: NCType[T]
    __metadata_key: bytes

    def __init__(self, storage: NCContractStorage, name: str, value: NCType[T]) -> None:
        self.__storage = storage
        self.__name = name
        self.__value = value
        self.__metadata_key = f'{name}{KEY_SEPARATOR}{_METADATA_KEY}'.encode()

    # Methods needed by StorageContainer:

    @override
    @classmethod
    def __check_name_and_type__(cls, name: str, type_: type[Sequence[T]]) -> None:
        if not name.isidentifier():
            raise NCTypeError('field name must be a valid identifier')
        origin_type: type[Sequence[T]] = not_none(get_origin(type_))
        if not issubclass(origin_type, Sequence):
            raise NCTypeError('expected Sequence type')
        args = get_args(type_)
        if not args or len(args) != 1:
            raise NCTypeError(f'expected {type_.__name__}[<item type>]')

    @override
    @classmethod
    def __from_name_and_type__(
        cls,
        storage: NCContractStorage,
        name: str,
        type_: type[Sequence[T]],
        /,
        *,
        type_map: Field.TypeMap,
    ) -> 'Self':
        item_type, = get_args(type_)
        item_nc_type = NCType.from_type(item_type, type_map=type_map.to_nc_type_map())
        return cls(storage, name, item_nc_type)

    # INTERNAL METHODS: all of these must be __dunder_methods so they aren't accessible from an OCB

    def __to_db_key(self, index: SupportsIndex) -> bytes:
        return f'{self.__name}{KEY_SEPARATOR}'.encode() + _INDEX_NC_TYPE.to_bytes(index.__index__())

    def __get_metadata(self) -> _DequeMetadata:
        metadata = self.__storage.get_obj(self.__metadata_key, _METADATA_NC_TYPE, default=None)

        if metadata is None:
            metadata = _DequeMetadata()
            self.__storage.put_obj(self.__metadata_key, _METADATA_NC_TYPE, metadata)

        assert isinstance(metadata, _DequeMetadata)
        return metadata

    def __update_metadata(self, new_metadata: _DequeMetadata) -> None:
        assert new_metadata.length >= 0
        if new_metadata.length == 0:
            return self.__storage.del_obj(self.__metadata_key)
        self.__storage.put_obj(self.__metadata_key, _METADATA_NC_TYPE, new_metadata)

    def __extend(self, *, items: Iterable[T], metadata: _DequeMetadata) -> None:
        new_last_index = metadata.last_index
        for item in items:
            new_last_index += 1
            key = self.__to_db_key(new_last_index)
            self.__storage.put_obj(key, self.__value, item)
        new_metadata = replace(metadata, length=new_last_index - metadata.first_index + 1)
        self.__update_metadata(new_metadata)

    def __extendleft(self, *, items: Iterable[T], metadata: _DequeMetadata) -> None:
        new_first_index = metadata.first_index
        for item in items:
            new_first_index -= 1
            key = self.__to_db_key(new_first_index)
            self.__storage.put_obj(key, self.__value, item)
        new_metadata = replace(
            metadata,
            first_index=new_first_index,
            length=metadata.last_index - new_first_index + 1,
        )
        self.__update_metadata(new_metadata)

    def __pop(self, *, metadata: _DequeMetadata, left: bool) -> T:
        if metadata.length == 0:
            raise NCIndexError

        index = metadata.first_index if left else metadata.last_index
        key = self.__to_db_key(index)
        item = self.__storage.get_obj(key, self.__value)
        self.__storage.del_obj(key)
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
            raise NCIndexError

        return metadata.last_index - idx if metadata.reversed else metadata.first_index + idx

    # Methods needed by MutableSequence and Sequence:

    def __getitem__(self, index: SupportsIndex, /) -> T:
        internal_index = self.__to_internal_index(index=index)
        key = self.__to_db_key(internal_index)
        return self.__storage.get_obj(key, self.__value)

    def __len__(self) -> int:
        return self.__get_metadata().length

    def __setitem__(self, index: SupportsIndex, value: T, /) -> None:
        internal_index = self.__to_internal_index(index=index)
        key = self.__to_db_key(internal_index)
        self.__storage.put_obj(key, self.__value, value)

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
            key = self.__to_db_key(i)
            yield self.__storage.get_obj(key, self.__value)

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
        raise NotImplementedError


DequeField = ContainerField[DequeStorageContainer[T]]
