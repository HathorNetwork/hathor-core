#  Copyright 2025 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing import Generic, NamedTuple, TypeVar, final

from typing_extensions import TYPE_CHECKING

from hathor.nanocontracts.fields.container import ContainerNodeFactory, TypeToContainerMap
from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint

T = TypeVar('T')


class Field(Generic[T]):
    """ This class is used to model the fields of a Blueprint from the signature that defines them.

    Fields are generally free to implement how they behave, but we have 2 types of behavior:

    - `self.foo = 1` will serialize `1` and save to db on a key derived from `'foo'` name
    - `self.foo['bar'] = 'baz'` will serialize and save to db on a key derive from `('foo', 'bar')`

    Usually only one of the two patterns above is supported by a field. The base class itself only defines how to
    construct a Field instance from a name and type signature, which is what the Blueprint metaclass needs.

    OCB safety considerations:

    - A Blueprint must not be able to access a Field instance directly
    """

    __slots__ = ('_prefix', '_container_node_factory')
    _prefix: bytes
    _container_node_factory: ContainerNodeFactory

    class TypeMap(NamedTuple):
        alias_map: TypeAliasMap
        nc_types_map: TypeToNCTypeMap
        container_map: TypeToContainerMap

        def to_nc_type_map(self) -> NCType.TypeMap:
            return NCType.TypeMap(self.alias_map, self.nc_types_map)

    # XXX: do we need to define field.__objclass__ for anything?

    def __init__(self, prefix: bytes, type_: type[T], type_map: TypeMap) -> None:
        self._prefix = prefix
        self._container_node_factory = ContainerNodeFactory(type_, type_map)

    @final
    @staticmethod
    def from_name_and_type(name: str, type_: type[T], /, *, type_map: TypeMap) -> Field[T]:
        assert name.isidentifier()
        prefix = name.encode('utf-8')
        return Field(prefix, type_, type_map)

    def _is_initialized(self, instance: Blueprint) -> bool:
        node = self._container_node_factory.build(instance)
        return node.has_value(self._prefix)

    def __set__(self, instance: Blueprint, value: T) -> None:
        node = self._container_node_factory.build(instance)
        node.set_value(self._prefix, value)

    def __get__(self, instance: Blueprint, owner: object | None = None) -> T:
        node = self._container_node_factory.build(instance)
        try:
            return node.get_value(self._prefix)
        except KeyError:
            raise AttributeError('attribute not initialized')

    def __delete__(self, instance: Blueprint) -> None:
        node = self._container_node_factory.build(instance)
        try:
            node.del_value(self._prefix)
        except KeyError:
            raise AttributeError('attribute not initialized')
