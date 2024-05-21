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

import hashlib
from typing import Any, Iterable

from typing_extensions import Self, override

from hathor.nanocontracts.fields import Field
from hathor.nanocontracts.fields.container_field import KEY_SEPARATOR, ContainerField, StorageContainer
from hathor.nanocontracts.storage import NCStorage
from hathor.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
)


class SetField(ContainerField['StorageSet']):
    __slots__ = ()

    VALID_VALUE_TYPES = {
        str,
        bytes,
        int,
        tuple,
        Address,
        Amount,
        BlueprintId,
        ContractId,
        Timestamp,
        TokenUid,
        TxOutputScript,
        VertexId,
    }

    @classmethod
    @override
    def create_from_name(cls, name: str, value_field: Field) -> Self:
        return cls(name, value_field, StorageSet)

    @classmethod
    @override
    def _validate_type_args(cls, name: str, args: list[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr
        if len(args) != 1:
            raise TypeError(f'set field `{name}` should have exactly one type argument')
        # TODO The correct criteria is that the value must be serializable.
        args0_origin = getattr(args[0], '__origin__', args[0])
        if args0_origin not in cls.VALID_VALUE_TYPES:
            raise TypeError(f'{name}: invalid value type {args[0]} {args0_origin}')
        # check that value type is valid
        value_field = get_field_for_attr('', args[0])
        return value_field


_LENGTH_KEY: str = '__length__'


class StorageSet(StorageContainer):
    __slots__ = ('__length_key',)

    def __init__(self, storage: NCStorage, name: str, value_field: Field) -> None:
        super().__init__(storage, name, value_field)
        self.__length_key = f'{name}{KEY_SEPARATOR}{_LENGTH_KEY}'

    def __to_db_key(self, elem: Any) -> str:
        data = self.__value_field__.to_bytes(elem)
        data_hash = hashlib.sha1(data).digest()
        return f'{self.__field_name__}{KEY_SEPARATOR}{data_hash.hex()}'

    def __get_length(self) -> int:
        return self.__storage__.get(self.__length_key, default=0)

    def __increase_length(self) -> None:
        self.__storage__.put(self.__length_key, self.__get_length() + 1)

    def __decrease_length(self) -> None:
        length = self.__get_length()
        assert length > 0
        self.__storage__.put(self.__length_key, length - 1)

    def add(self, elem: Any) -> None:
        key = self.__to_db_key(elem)
        if self.__storage__.contains(key):
            return
        self.__storage__.put(key, elem)
        self.__increase_length()

    def remove(self, elem: Any) -> None:
        key = self.__to_db_key(elem)
        if not self.__storage__.contains(key):
            raise KeyError
        self.__storage__.delete(key)
        self.__decrease_length()

    def discard(self, elem: Any) -> None:
        key = self.__to_db_key(elem)
        if not self.__storage__.contains(key):
            return
        self.__storage__.delete(key)
        self.__decrease_length()

    def __contains__(self, elem: Any) -> bool:
        key = self.__to_db_key(elem)
        return self.__storage__.contains(key)

    def __len__(self) -> int:
        return self.__get_length()

    def isdisjoint(self, other: set[Any]) -> bool:
        return len(self.intersection(other)) == 0

    def issuperset(self, other: Iterable[Any]) -> bool:
        return all(elem in self for elem in other)

    def intersection(self, other: Iterable[Any]) -> set[Any]:
        return set(elem for elem in other if elem in self)

    def update(self, *others: Iterable[Any]) -> None:
        for other in others:
            for elem in other:
                self.add(elem)

    def difference_update(self, *others: Iterable[Any]) -> None:
        for other in others:
            for elem in other:
                self.discard(elem)
