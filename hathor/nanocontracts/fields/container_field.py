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

from abc import ABC, abstractmethod
from collections.abc import Container
from typing import Generic, TypeVar

from typing_extensions import TYPE_CHECKING, Self, override

from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none
from hathor.utils.typing import InnerTypeMixin, get_origin

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint

C = TypeVar('C', bound=Container)

KEY_SEPARATOR: str = ':'


class StorageContainer(Generic[C], ABC):
    """ Abstraction over the class that will be returned when accessing a container field.

    Every method and property in this class should use either `__dunder` or `__special__` naming pattern, because
    otherwise the property/method would be accessible from an OCB. Even if there would be no harm, this is generally
    avoided.
    """
    __slots__ = ()

    @classmethod
    @abstractmethod
    def __check_name_and_type__(cls, name: str, type_: type[C]) -> None:
        """Should raise a TypeError if the given name or type is incompatible for use with container."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def __from_name_and_type__(
        cls,
        storage: NCContractStorage,
        name: str,
        type_: type[C],
        /,
        *,
        type_map: Field.TypeMap,
    ) -> Self:
        """Every StorageContainer should be able to be built with this signature.

        Expect a type that has been previously checked with `cls.__check_name_and_type__`.
        """
        raise NotImplementedError


T = TypeVar('T', bound=StorageContainer)


class ContainerField(InnerTypeMixin[T], Field[T]):
    """ This class models a Field with a StorageContainer, it can't be set, only accessed as a container.

    This is modeled after a Python descriptor, similar to the built in `property`, see:

    - https://docs.python.org/3/reference/datamodel.html#implementing-descriptors

    The observed value behaves like a container, the specific behavior depends on the container type.
    """

    __slots__ = ('__name', '__type', '__type_map')
    __name: str
    __type: type[T]
    __type_map: Field.TypeMap

    # XXX: customize InnerTypeMixin behavior so it stores the origin type, since that's what we want
    @classmethod
    def __extract_inner_type__(cls, args: tuple[type, ...], /) -> type[T]:
        inner_type: type[T] = InnerTypeMixin.__extract_inner_type__(args)
        return not_none(get_origin(inner_type))

    @override
    @classmethod
    def _from_name_and_type(cls, name: str, type_: type[T], /, *, type_map: Field.TypeMap) -> Self:
        if not issubclass(cls.__inner_type__, StorageContainer):
            raise TypeError(f'{cls.__inner_type__} is not a StorageContainer')
        cls.__inner_type__.__check_name_and_type__(name, type_)
        field = cls()
        field.__name = name
        field.__type = type_
        field.__type_map = type_map
        return field

    @override
    def __set__(self, instance: Blueprint, value: T) -> None:
        # XXX: alternatively this could mimick a `my_container.clear(); my_container.update(value)`
        raise AttributeError('cannot set a container field')

    @override
    def __get__(self, instance: Blueprint, owner: object | None = None) -> T:
        if obj := instance.syscall.__cache__.get(self.__name):
            return obj

        # XXX: ideally we would instantiate the storage within _from_name_and_type, but we need the blueprint instance
        #      and we only have access to it when __get__ is called the first time
        storage = self.__inner_type__.__from_name_and_type__(
            instance.syscall.__storage__,
            self.__name,
            self.__type,
            type_map=self.__type_map,
        )
        instance.syscall.__cache__[self.__name] = storage
        return storage

    @override
    def __delete__(self, instance: Blueprint) -> None:
        # XXX: alternatively delete the database
        raise AttributeError('cannot delete a container field')
