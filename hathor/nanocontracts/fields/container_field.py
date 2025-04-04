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

from abc import ABC, abstractmethod
from typing import Any, Callable, Generic, TypeAlias, TypeVar

from typing_extensions import Self

from hathor.nanocontracts.fields import Field
from hathor.nanocontracts.storage import NCStorage
from hathor.serialization import Deserializer, Serializer

T = TypeVar('T', bound='StorageContainer')
StorageFactoryType: TypeAlias = Callable[[NCStorage, str, Field], T]

KEY_SEPARATOR: str = ':'


class ContainerField(Field, ABC, Generic[T]):
    __slots__ = ('__name', '__value_field', '__storage_factory')

    def __init__(self, name: str, value_field: Field, storage_factory: StorageFactoryType) -> None:
        self.__name = name
        self.__value_field = value_field
        self.__storage_factory = storage_factory

    @classmethod
    @abstractmethod
    def create_from_name(cls, name: str, value_field: Field) -> Self:
        raise NotImplementedError

    @classmethod
    def create_from_type(cls, name: str, type_: type[Any]) -> Self:
        args = getattr(type_, '__args__', [])
        value_field = cls._validate_type_args(name, args)
        return cls.create_from_name(name, value_field)

    @classmethod
    @abstractmethod
    def _validate_type_args(cls, name: str, args: list[Any]) -> Field:
        raise NotImplementedError

    def __set__(self, blueprint, value):
        raise AttributeError('cannot set a container field')

    def __get__(self, blueprint, objtype):
        if obj := blueprint._cache.get(self.__name):
            return obj

        storage = self.__storage_factory(blueprint._storage, self.__name, self.__value_field)
        blueprint._cache[self.__name] = storage
        return storage

    def serialize(self, serializer: Serializer, value: Any) -> None:
        raise AssertionError('container fields cannot be used directly')

    def deserialize(self, deserializer: Deserializer) -> Any:
        raise AssertionError('container fields cannot be used directly')

    def isinstance(self, value: Any) -> bool:
        raise AssertionError('container fields cannot be used directly')


class StorageContainer:
    __slots__ = ('__storage__', '__field_name__', '__value_field__')

    def __init__(self, storage: NCStorage, name: str, value_field: Field) -> None:
        self.__storage__ = storage
        self.__field_name__ = name
        self.__value_field__ = value_field
