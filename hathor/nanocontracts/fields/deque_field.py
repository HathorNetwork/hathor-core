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

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from typing_extensions import Self, override

from hathor.nanocontracts.fields import Field
from hathor.nanocontracts.fields.container_field import KEY_SEPARATOR, ContainerField, StorageContainer
from hathor.nanocontracts.storage import NCContractStorage


class DequeField(ContainerField['StorageDeque']):
    __slots__ = ()

    @classmethod
    @override
    def create_from_name(cls, name: str, value_field: Field) -> Self:
        return cls(name, value_field, StorageDeque)

    @classmethod
    @override
    def _validate_type_args(cls, name: str, args: list[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr
        if len(args) != 1:
            raise TypeError(f'deque field `{name}` must have exactly one type argument')
        # check that value type is valid
        value_field = get_field_for_attr('', args[0])
        return value_field


_METADATA_KEY: str = '__metadata__'


@dataclass(slots=True, frozen=True, kw_only=True)
class _StorageDequeMetadata:
    first_index: int
    length: int
    reversed: bool

    @property
    def last_index(self) -> int:
        return self.first_index + self.length - 1


class StorageDeque(StorageContainer):
    __slots__ = ('__metadata_key',)

    def __init__(self, storage: NCContractStorage, name: str, value_field: Field) -> None:
        super().__init__(storage, name, value_field)
        self.__metadata_key = f'{name}{KEY_SEPARATOR}{_METADATA_KEY}'

    def __to_db_key(self, index: int) -> str:
        return f'{self.__field_name__}{KEY_SEPARATOR}{index}'

    def __get_or_create_metadata(self) -> _StorageDequeMetadata:
        metadata = self.__storage__.get(self.__metadata_key, default=None)

        if metadata is None:
            metadata = _StorageDequeMetadata(first_index=0, length=0, reversed=False)
            self.__storage__.put(self.__metadata_key, metadata)

        assert isinstance(metadata, _StorageDequeMetadata)
        return metadata

    def __update_metadata(self, new_metadata: _StorageDequeMetadata) -> None:
        assert new_metadata.length >= 0
        if new_metadata.length == 0:
            return self.__storage__.delete(self.__metadata_key)
        self.__storage__.put(self.__metadata_key, new_metadata)

    @property
    def maxlen(self) -> int | None:
        return None

    def append(self, item: Any) -> None:
        self.extend((item,))

    def appendleft(self, item: Any) -> None:
        self.extendleft((item,))

    def extend(self, items: Iterable[Any]) -> None:
        metadata = self.__get_or_create_metadata()
        if metadata.reversed:
            return self.__extendleft(items=items, metadata=metadata)
        self.__extend(items=items, metadata=metadata)

    def __extend(self, *, items: Iterable[Any], metadata: _StorageDequeMetadata) -> None:
        new_last_index = metadata.last_index
        for item in items:
            new_last_index += 1
            key = self.__to_db_key(new_last_index)
            self.__storage__.put(key, item)
        new_metadata = dataclasses.replace(metadata, length=new_last_index - metadata.first_index + 1)
        self.__update_metadata(new_metadata)

    def extendleft(self, items: Iterable[Any]) -> None:
        metadata = self.__get_or_create_metadata()
        if metadata.reversed:
            return self.__extend(items=items, metadata=metadata)
        self.__extendleft(items=items, metadata=metadata)

    def __extendleft(self, *, items: Iterable[Any], metadata: _StorageDequeMetadata) -> None:
        new_first_index = metadata.first_index
        for item in items:
            new_first_index -= 1
            key = self.__to_db_key(new_first_index)
            self.__storage__.put(key, item)
        new_metadata = dataclasses.replace(
            metadata,
            first_index=new_first_index,
            length=metadata.last_index - new_first_index + 1,
        )
        self.__update_metadata(new_metadata)

    def pop(self) -> Any:
        metadata = self.__get_or_create_metadata()
        return self.__pop(metadata=metadata, left=metadata.reversed)

    def popleft(self) -> Any:
        metadata = self.__get_or_create_metadata()
        return self.__pop(metadata=metadata, left=not metadata.reversed)

    def __pop(self, *, metadata: _StorageDequeMetadata, left: bool) -> Any:
        if metadata.length == 0:
            raise IndexError

        index = metadata.first_index if left else metadata.last_index
        key = self.__to_db_key(index)
        item = self.__storage__.get(key)
        self.__storage__.delete(key)
        new_metadata = dataclasses.replace(
            metadata,
            first_index=metadata.first_index + 1 if left else metadata.first_index,
            length=metadata.length - 1
        )
        self.__update_metadata(new_metadata)
        return item

    def reverse(self) -> None:
        metadata = self.__get_or_create_metadata()
        new_metadata = dataclasses.replace(metadata, reversed=not metadata.reversed)
        self.__update_metadata(new_metadata)

    def __iter__(self) -> Iterator[Any]:
        metadata = self.__get_or_create_metadata()
        indexes = range(metadata.first_index, metadata.last_index + 1)

        if metadata.reversed:
            indexes = range(metadata.last_index, metadata.first_index - 1, -1)

        for i in indexes:
            key = self.__to_db_key(i)
            yield self.__storage__.get(key)

    def __len__(self) -> int:
        metadata = self.__get_or_create_metadata()
        return metadata.length

    def __to_internal_index(self, *, index: int) -> int:
        metadata = self.__get_or_create_metadata()

        if index < 0:
            index += metadata.length

        if index < 0 or index >= metadata.length:
            raise IndexError

        return metadata.last_index - index if metadata.reversed else metadata.first_index + index

    def __setitem__(self, index: int, value: Any) -> None:
        internal_index = self.__to_internal_index(index=index)
        key = self.__to_db_key(internal_index)
        self.__storage__.put(key, value)

    def __getitem__(self, index: int) -> Any:
        internal_index = self.__to_internal_index(index=index)
        key = self.__to_db_key(internal_index)
        return self.__storage__.get(key)
