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

from abc import ABC, abstractmethod
from typing import Generic, NamedTuple, TypeVar, final, get_origin

from typing_extensions import TYPE_CHECKING, Self

from hathor.nanocontracts.fields.utils import TypeToFieldMap
from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint

T = TypeVar('T')


class Field(Generic[T], ABC):
    """ This class is used to model the fields of a Blueprint from the signature that defines them.

    Fields are generally free to implement how they behave, but we have 2 types of behavior:

    - `self.foo = 1` will serialize `1` and save to db on a key derived from `'foo'` name
    - `self.foo['bar'] = 'baz'` will serialize and save to db on a key derive from `('foo', 'bar')`

    Usually only one of the two patterns above is supported by a field. The base class itself only defines how to
    construct a Field instance from a name and type signature, which is what the Blueprint metaclass needs.


    OCB safety considerations:

    - A Blueprint must not be able to access a Field instance directly
    """

    class TypeMap(NamedTuple):
        alias_map: TypeAliasMap
        nc_types_map: TypeToNCTypeMap
        fields_map: TypeToFieldMap

        def to_nc_type_map(self) -> NCType.TypeMap:
            return NCType.TypeMap(self.alias_map, self.nc_types_map)

    # XXX: do we need to define field.__objclass__ for anything?

    @final
    @staticmethod
    def from_name_and_type(name: str, type_: type[T], /, *, type_map: TypeMap) -> Field[T]:
        from hathor.nanocontracts.fields.nc_type_field import NCTypeField

        # if we have a `dict[int, int]` we use `get_origin()` to get the `dict` part, since it's a different instance
        origin_type = get_origin(type_) or type_

        if origin_type in type_map.fields_map:
            field_class = type_map.fields_map[origin_type]
            return field_class._from_name_and_type(name, type_, type_map=type_map)
        else:
            try:
                return NCTypeField._from_name_and_type(name, type_, type_map=type_map)
            except TypeError as e:
                raise TypeError(f'type {type_} is not supported by any Field class') from e

    @classmethod
    @abstractmethod
    def _from_name_and_type(cls, name: str, type_: type[T], /, *, type_map: TypeMap) -> Self:
        raise NotImplementedError

    @abstractmethod
    def __set__(self, instance: Blueprint, value: T) -> None:
        # called when doing `instance.field = value`
        raise NotImplementedError

    @abstractmethod
    def __get__(self, instance: Blueprint, owner: object | None = None) -> T:
        # called when doing `instance.field` as an expression
        raise NotImplementedError

    @abstractmethod
    def __delete__(self, instance: Blueprint) -> None:
        # called when doing `del instance.field`
        raise NotImplementedError
