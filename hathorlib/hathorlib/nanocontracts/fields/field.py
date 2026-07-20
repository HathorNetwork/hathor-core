# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from typing import Generic, NamedTuple, TypeVar, final

from typing_extensions import TYPE_CHECKING

from hathorlib.nanocontracts.fields.container import ContainerNode, ContainerNodeFactory, TypeToContainerMap
from hathorlib.nanocontracts.nc_types import NCType
from hathorlib.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap
from hathorlib.nanocontracts.storage_version import get_storage_token_amount_version
from hathorlib.token_amount_version import TokenAmountVersion

if TYPE_CHECKING:
    from hathorlib.nanocontracts.blueprint import Blueprint

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

    __slots__ = ('_prefix', '_container_node_factories')
    _prefix: bytes
    _container_node_factories: Mapping[TokenAmountVersion, ContainerNodeFactory[T]]

    class TypeMap(NamedTuple):
        alias_map: TypeAliasMap
        nc_types_map: TypeToNCTypeMap
        container_map: TypeToContainerMap

        def to_nc_type_map(self) -> NCType.TypeMap:
            return NCType.TypeMap(self.alias_map, self.nc_types_map)

    # XXX: do we need to define field.__objclass__ for anything?

    def __init__(self, prefix: bytes, type_: type[T], type_maps: Mapping[TokenAmountVersion, TypeMap]) -> None:
        self._prefix = prefix
        self._container_node_factories = {
            version: ContainerNodeFactory[T](type_, type_map) for version, type_map in type_maps.items()
        }

    @final
    @staticmethod
    def from_name_and_type(
        name: str,
        type_: type[T],
        /,
        *,
        type_maps: Mapping[TokenAmountVersion, TypeMap],
    ) -> Field[T]:
        assert name.isidentifier()
        prefix = name.encode('utf-8')
        return Field(prefix, type_, type_maps)

    def _build_node(self, instance: Blueprint) -> ContainerNode[T]:
        """Build the container node with the globally-selected storage serialization version."""
        factory = self._container_node_factories[get_storage_token_amount_version()]
        return factory.build(instance)

    def _is_initialized(self, instance: Blueprint) -> bool:
        node = self._build_node(instance)
        return node.has_value(self._prefix)

    def __set__(self, instance: Blueprint, value: T) -> None:
        node = self._build_node(instance)
        node.set_value(self._prefix, value)

    def __get__(self, instance: Blueprint, owner: object | None = None) -> T:
        node = self._build_node(instance)
        try:
            return node.get_value(self._prefix)
        except KeyError:
            raise AttributeError('attribute not initialized')

    def __delete__(self, instance: Blueprint) -> None:
        node = self._build_node(instance)
        try:
            node.del_value(self._prefix)
        except KeyError:
            raise AttributeError('attribute not initialized')
