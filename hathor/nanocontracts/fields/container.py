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
from collections.abc import Container as ContainerAbc, Mapping
from typing import ClassVar, Generic, TypeAlias, TypeVar

from typing_extensions import TYPE_CHECKING, Self, final, get_origin, override

from hathor.nanocontracts.blueprint_env import NCAttrCache
from hathor.nanocontracts.nc_types import BoolNCType, NCType
from hathor.nanocontracts.storage import NCContractStorage

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint
    from hathor.nanocontracts.fields.field import Field

T = TypeVar('T')

KEY_SEPARATOR: bytes = b':'
INIT_KEY: bytes = b'__init__'
INIT_NC_TYPE: NCType[bool] = BoolNCType()


class Container(Generic[T], ABC):
    """ Abstraction over the class that will be returned when accessing a container field.

    Every method and property in this class should use either `__dunder` or `__special__` naming pattern, because
    otherwise the property/method would be accessible from an OCB. Even if there would be no harm, this is generally
    avoided.
    """
    __slots__ = ('__storage__', '__prefix__')
    __storage__: NCContractStorage
    __prefix__: bytes

    @classmethod
    @abstractmethod
    def __check_type__(cls, type_: type[ContainerAbc[T]], type_map: Field.TypeMap) -> None:
        """Should raise a TypeError if the given name or type is incompatible for use with container."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
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
        """Every Container should be able to be built with this signature.

        Expect a type that has been previously checked with `cls.__check_type__`.
        """
        raise NotImplementedError

    @abstractmethod
    def __init_storage__(self, initial_value: ContainerAbc[T] | None = None) -> None:
        """Containers should use this to initialize metadata/length values."""
        raise NotImplementedError

    def __is_initialized__(self) -> bool:
        """Used to initialize the container if it's not already initialized.

        When a Blueprint class is built, the initialize() method is patched by the metaclass to call this method on
        every container field, so at the end of calling initialize() call, it's guaranteed that every container will
        have been initialized.
        """
        is_init_key = KEY_SEPARATOR.join([self.__prefix__, INIT_KEY])
        return self.__storage__.get_obj(is_init_key, INIT_NC_TYPE, default=False)


TypeToContainerMap: TypeAlias = Mapping[type[ContainerAbc], type[Container]]


P = TypeVar('P', bound=Container)


class ContainerNodeFactory(Generic[T]):
    __slots__ = ('type_', 'type_map')
    type_: type[T]
    type_map: Field.TypeMap

    @classmethod
    def check_is_container(cls, type_: type[T], type_map: Field.TypeMap) -> bool:
        """ Checks that the given type can be used with the given type_map, also returns whether it is a container.
        """
        # if we have a `dict[int, int]` we use `get_origin()` to get the `dict` part, since it's a different instance
        origin_type = get_origin(type_) or type_

        if origin_type in type_map.container_map:
            container_class = type_map.container_map[origin_type]  # type: ignore[index]
            container_class.__check_type__(type_, type_map)  # type: ignore[arg-type]
            return True
        else:
            NCType.check_type(type_, type_map=type_map.to_nc_type_map())
            return False

    def __init__(self, type_: type[T], type_map: Field.TypeMap) -> None:
        self.type_ = type_
        self.type_map = type_map
        self.check_is_container(type_, type_map)

    def build(self, instance: Blueprint) -> ContainerNode:
        return ContainerNode.from_type(
            instance.syscall.__storage__,
            self.type_,
            type_map=self.type_map,
            cache=instance.syscall.__cache__,
        )


class ContainerNode(ABC, Generic[T]):
    """This class is used by containers to abstract over either a Value or another Container.

    For example, consider something like this:

    ```
    class MyBlueprint(Blueprint):
        foo: dict[int, int]
        bar: dict[int, list[int]]
    ```

    Both `foo` and `bar` will be abstracted with a `DictContainer`, but when doing `foo[1]` or `bar[1]` a
    `ContainerNode` is used to decide whether to use a `NCType` (in case of `foo`) or another `DictContainer`
    (with a new prefix, in case of `bar`).
    """
    __slots__ = ('storage', 'cache')  # subclasses must define the appropriate slots
    is_leaf: ClassVar[bool]
    storage: NCContractStorage
    cache: NCAttrCache

    def __init__(self, storage: NCContractStorage, cache: NCAttrCache):
        self.storage = storage
        self.cache = cache

    @final
    @staticmethod
    def from_type(
        storage: NCContractStorage,
        type_: type[T],
        /,
        *,
        cache: NCAttrCache,
        type_map: Field.TypeMap,
    ) -> ContainerNode[T]:
        origin_type = get_origin(type_) or type_

        if origin_type in type_map.container_map:
            container_class = type_map.container_map[origin_type]  # type: ignore[index]
            return ContainerProxy(storage, cache, type_, type_map, container_class)  # type: ignore[type-var]
        else:
            nc_type = NCType.from_type(type_, type_map=type_map.to_nc_type_map())
            return ContainerLeaf(storage, nc_type, cache)

    @abstractmethod
    def has_value(self, prefix: bytes) -> bool:
        """Whether the value/container exists in the storage."""
        raise NotImplementedError

    @abstractmethod
    def get_value(self, prefix: bytes) -> T:
        """Resolves to returning either an actual value, or a proxy storage container."""
        raise NotImplementedError

    @abstractmethod
    def set_value(self, prefix: bytes, value: T) -> None:
        """Represents an assignment to the value or proxy container."""
        raise NotImplementedError

    @abstractmethod
    def del_value(self, prefix: bytes) -> None:
        """What to do when the value is deleted/popped."""
        raise NotImplementedError


@final
class ContainerProxy(ContainerNode[P]):
    """A type of container that isn't a value, but delegates storing actual values to child container nodes."""

    __slots__ = ('storage', 'cache', '_type', '_type_map', '_container_class')
    is_leaf = False

    _type: type[P]
    _type_map: Field.TypeMap
    _container_class: type[Container[P]]

    def __init__(
        self,
        storage: NCContractStorage,
        cache: NCAttrCache,
        type_: type[P],
        type_map: Field.TypeMap,
        container_class: type[Container],
    ) -> None:
        super().__init__(storage, cache)
        self._type = type_
        self._type_map = type_map
        self._container_class = container_class

    def _build_container(self, prefix: bytes) -> Container:
        return self._container_class.__from_prefix_and_type__(
            self.storage,
            prefix,
            self._type,  # type: ignore[arg-type]
            cache=self.cache,
            type_map=self._type_map,
        )

    @override
    def has_value(self, prefix: bytes) -> bool:
        if self.cache is not None and prefix in self.cache:
            return True

        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        # XXX: is init indicates whether the container exists or not
        is_init = self.storage.get_obj(is_init_key, INIT_NC_TYPE, default=False)
        return is_init

    @override
    def get_value(self, prefix: bytes) -> P:
        if self.cache is not None and prefix in self.cache:
            return self.cache[prefix]

        container = self._build_container(prefix)
        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        is_init = self.storage.get_obj(is_init_key, INIT_NC_TYPE, default=False)
        if not is_init:
            raise ValueError('not initialized')

        if self.cache is not None:
            self.cache[prefix] = container

        # XXX: ignore return-value because mypy doesn't know that the built Container is our P
        return container  # type: ignore[return-value]

    @override
    def set_value(self, prefix: bytes, value: P) -> None:
        container = self._build_container(prefix)
        if isinstance(value, Container):
            if value == container:
                # XXX: no-op
                return
            else:
                raise ValueError('invalid assigned value')
        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        is_init = self.storage.get_obj(is_init_key, INIT_NC_TYPE, default=False)
        if is_init:
            raise ValueError('already initialized')
        # XXX: ignore arg-type, it is correct but hard to typ
        container.__init_storage__(value)
        self.storage.put_obj(is_init_key, INIT_NC_TYPE, True)
        if self.cache is not None:
            self.cache[prefix] = container

    @override
    def del_value(self, prefix: bytes) -> None:
        container = self._build_container(prefix)
        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        # XXX: container is implicitly Sized, it still has to be made explicit
        if len(container) != 0:  # type: ignore[arg-type]
            raise ValueError('container is not empty')
        self.storage.del_obj(is_init_key)
        if self.cache is not None and prefix in self.cache:
            del self.cache[prefix]


@final
class ContainerLeaf(ContainerNode[T]):
    """A container-leaf resolves to an actual value and thus has a NCType that it uses to (de)serialize values."""

    __slots__ = ('storage', 'cache', '_nc_type')
    is_leaf = True

    _nc_type: NCType[T]

    def __init__(self, storage: NCContractStorage, nc_type: NCType[T], cache: NCAttrCache = None) -> None:
        super().__init__(storage, cache)
        self._nc_type = nc_type

    @override
    def has_value(self, prefix: bytes) -> bool:
        if self.cache is not None and prefix in self.cache:
            return True
        return self.storage.has_obj(prefix)

    @override
    def get_value(self, prefix: bytes) -> T:
        if self.cache is not None and prefix in self.cache:
            return self.cache[prefix]
        obj = self.storage.get_obj(prefix, self._nc_type)
        if self.cache is not None:
            self.cache[prefix] = obj
        return obj

    @override
    def set_value(self, prefix: bytes, value: T) -> None:
        self.storage.put_obj(prefix, self._nc_type, value)
        if self.cache is not None:
            self.cache[prefix] = value

    @override
    def del_value(self, prefix: bytes) -> None:
        self.storage.del_obj(prefix)
        if self.cache is not None and prefix in self.cache:
            del self.cache[prefix]
