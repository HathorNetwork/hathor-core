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
from typing import Generic, TypeAlias, TypeVar

from typing_extensions import TYPE_CHECKING, Self, final, get_origin, override

from hathor.nanocontracts.nc_types import BoolNCType, NCType
from hathor.nanocontracts.storage import NCContractStorage

if TYPE_CHECKING:
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
    __slots__ = ()

    @classmethod
    @abstractmethod
    def __check_type__(cls, type_: type[ContainerAbc[T]]) -> None:
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
        type_map: Field.TypeMap,
    ) -> Self:
        """Every Container should be able to be built with this signature.

        Expect a type that has been previously checked with `cls.__check_type__`.
        """
        raise NotImplementedError

    @abstractmethod
    def __init_storage__(self) -> None:
        """Containers should use this to initialize metadata/length values."""
        raise NotImplementedError


TypeToContainerMap: TypeAlias = Mapping[type[ContainerAbc], type[Container]]


P = TypeVar('P', bound=Container)


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

    @final
    @staticmethod
    def from_type(storage: NCContractStorage, type_: type[T], /, *, type_map: Field.TypeMap) -> ContainerNode[T]:
        origin_type = get_origin(type_) or type_

        if origin_type in type_map.container_map:
            container_class = type_map.container_map[origin_type]
            container_class.__check_type__(type_)
            return ContainerProxy(storage, type_, type_map, container_class)
        else:
            nc_type = NCType.from_type(type_, type_map=type_map.to_nc_type_map())
            return ContainerLeaf(storage, nc_type)

    @abstractmethod
    def get_value(self, prefix: bytes) -> T:
        """Resolves to returning either an actual value, or a proxy storage container."""
        raise NotImplementedError

    @abstractmethod
    def set_value(self, prefix: bytes, value: T) -> None:
        """"""
        raise NotImplementedError

    @abstractmethod
    def del_value(self, prefix: bytes) -> None:
        """"""
        raise NotImplementedError


class ContainerProxy(ContainerNode[P]):
    """"""

    _storage: NCContractStorage
    _type: type[P]
    _type_map: Field.TypeMap
    _container_class: type[Container[P]]

    def __init__(
        self,
        storage: NCContractStorage,
        type_: type[P],
        type_map: Field.TypeMap,
        container_class: type[Container],
    ) -> None:
        self._storage = storage
        self._type = type_
        self._type_map = type_map
        self._container_class = container_class

    def _build_container(self, prefix: bytes) -> Container:
        return self._container_class.__from_prefix_and_type__(
            self._storage,
            prefix,
            self._type,
            type_map=self._type_map,
        )

    @override
    def get_value(self, prefix: bytes) -> P:
        container = self._build_container(prefix)
        is_init_key = KEY_SEPARATOR.join([prefix, INIT_KEY])
        is_init = self._storage.get_obj(is_init_key, INIT_NC_TYPE, default=False)
        if not is_init:
            container.__init_storage__()
            self._storage.put_obj(is_init_key, INIT_NC_TYPE, True)
        # XXX: ignore return value because mypy doesn't know that the built Container is our P
        return container  # type: ignore[return-value]

    @override
    def set_value(self, prefix: bytes, value: P) -> None:
        # XXX:
        pass

    @override
    def del_value(self, prefix: bytes) -> None:
        # XXX: just ignore? maybe accept deleting when length is zero?
        pass


class ContainerLeaf(ContainerNode[T]):
    """A container-leaf resolves to an actual value and thus has a NCType that it uses to (de)serialize values."""

    _storage: NCContractStorage
    _nc_type: NCType[T]

    def __init__(self, storage: NCContractStorage, nc_type: NCType[T]) -> None:
        self._storage = storage
        self._nc_type = nc_type

    @override
    def get_value(self, prefix: bytes) -> T:
        return self._storage.get_obj(prefix, self._nc_type)

    @override
    def set_value(self, prefix: bytes, value: T) -> None:
        self._storage.put_obj(prefix, self._nc_type, value)

    @override
    def del_value(self, prefix: bytes) -> None:
        self._storage.del_obj(prefix)
