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

from collections.abc import Container as ContainerAbc
from typing import TypeVar

from typing_extensions import TYPE_CHECKING, Self, cast, override

from hathor.nanocontracts.fields.container import INIT_KEY, INIT_NC_TYPE, KEY_SEPARATOR, Container
from hathor.nanocontracts.fields.field import Field
from hathor.util import not_none
from hathor.utils.typing import InnerTypeMixin, get_origin

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint


T = TypeVar('T')


class ContainerField(InnerTypeMixin[Container[T]], Field[ContainerAbc[T]]):
    """ This class models a Field with a Container, it can't be set, only accessed as a container.

    This is modeled after a Python descriptor, similar to the built in `property`, see:

    - https://docs.python.org/3/reference/datamodel.html#implementing-descriptors

    The observed value behaves like a container, the specific behavior depends on the container type.
    """

    __slots__ = ('__name', '__type', '__type_map')
    __name: str
    __type: type[ContainerAbc[T]]
    __type_map: Field.TypeMap

    # XXX: customize InnerTypeMixin behavior so it stores the origin type, since that's what we want
    @classmethod
    def __extract_inner_type__(cls, args: tuple[type, ...], /) -> type[Container[T]]:
        inner_type: type[Container[T]] = InnerTypeMixin.__extract_inner_type__(args)
        return not_none(get_origin(inner_type))

    @override
    @classmethod
    def _from_name_and_type(cls, name: str, type_: type[ContainerAbc[T]], /, *, type_map: Field.TypeMap) -> Self:
        if not issubclass(cls.__inner_type__, Container):
            raise TypeError(f'{cls.__inner_type__} is not a Container')
        if not name.isidentifier():
            raise TypeError('field name must be a valid identifier')
        cls.__inner_type__.__check_type__(type_)
        field = cls()
        field.__name = name
        field.__type = type_
        field.__type_map = type_map
        return field

    @override
    def __set__(self, instance: Blueprint, value: ContainerAbc[T]) -> None:
        # XXX: alternatively this could mimick a `my_container.clear(); my_container.update(value)`
        raise AttributeError('cannot set a container field')

    @override
    def __get__(self, instance: Blueprint, owner: object | None = None) -> ContainerAbc[T]:
        cache = instance.syscall.__cache__
        if cache is not None and (obj := cache.get(self.__name)):
            return obj

        storage = instance.syscall.__storage__
        prefix = self.__name.encode('utf-8')
        # XXX: the following block of code is very similar to what is don inside `ContainerProxy.get_value`
        container: Container[T] = self.__inner_type__.__from_prefix_and_type__(
            storage,
            prefix,
            self.__type,
            type_map=self.__type_map,
        )
        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        is_init = storage.get_obj(is_init_key, INIT_NC_TYPE, default=False)
        if not is_init:
            container.__init_storage__()
            storage.put_obj(is_init_key, INIT_NC_TYPE, True)
        if cache is not None:
            cache[self.__name] = container
        # XXX: it's OK to do this cast because a Container[T] behaves like a ContainerAbc[T]
        return cast(ContainerAbc[T], container)

    @override
    def __delete__(self, instance: Blueprint) -> None:
        # XXX: alternatively delete the database
        raise AttributeError('cannot delete a container field')
