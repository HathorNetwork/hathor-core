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

"""
This NCType class is not meant for use in a TypeMap, it is meant to facilitate creating NCType classes for simple
dataclasses for easily making them accessible to NCStorage.

In theory it could be generalized for use in the future but we have to be careful with supporting types defined inside
and OCB and the mapping logic will need to be adapted or special cased to support this.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.nc_types.optional_nc_type import OptionalNCType
from hathor.serialization import Deserializer, Serializer

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

    from hathor.nanocontracts.nc_types import TypeToNCTypeMap

D = TypeVar('D', bound='DataclassInstance')


def make_dataclass_nc_type(
    class_: type[D],
    *,
    extra_nc_types_map: TypeToNCTypeMap | None = None,
) -> DataclassNCType[D]:
    """ Helper function to build a NCType for the given dataclass.
    """
    from hathor.nanocontracts.nc_types import DEFAULT_TYPE_ALIAS_MAP, RETURN_TYPE_TO_NC_TYPE_MAP
    alias_map = DEFAULT_TYPE_ALIAS_MAP
    extras = extra_nc_types_map or {}
    nc_types_map = {**RETURN_TYPE_TO_NC_TYPE_MAP, **extras}
    type_map = NCType.TypeMap(alias_map, nc_types_map)
    return DataclassNCType._from_type(class_, type_map=type_map)


def make_dataclass_opt_nc_type(class_: type[D]) -> OptionalNCType[D]:
    """ Helper function to build an OptionalNCType for the given dataclass.
    """
    return OptionalNCType(make_dataclass_nc_type(class_))


class DataclassNCType(NCType[D]):
    __slots__ = ('_fields', '_class')
    _is_hashable = False  # it might be possible to calculate _is_hashable, but we don't need it
    _fields: dict[str, NCType]
    _class: type[D]

    def __init__(self, fields_: dict[str, NCType], class_: type[D]):
        self._fields = fields_
        self._class = class_

    @override
    @classmethod
    def _from_type(cls, type_: type[D], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_dataclass(type_):
            raise TypeError('expected a dataclass')
        # XXX: the order is important, but `dict` and `fields` should have a stable order
        values: dict[str, NCType] = {}
        for field in fields(type_):
            values[field.name] = NCType.from_type(field.type, type_map=type_map)  # type: ignore[arg-type]
        return cls(values, type_)

    @override
    def _check_value(self, value: D, /, *, deep: bool) -> None:
        if not isinstance(value, self._class):
            raise TypeError(f'expected {self._class} instance')

    @override
    def _serialize(self, serializer: Serializer, value: D, /) -> None:
        for field_name, field_nc_type in self._fields.items():
            field_nc_type.serialize(serializer, getattr(value, field_name))

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> D:
        kwargs: dict[str, Any] = {}
        for field_name, field_nc_type in self._fields.items():
            kwargs[field_name] = field_nc_type.deserialize(deserializer)
        return self._class(**kwargs)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> D:
        if not isinstance(json_value, dict):
            raise ValueError('expected dict')
        kwargs: dict[str, Any] = {}
        for field_name, field_nc_type in self._fields.items():
            kwargs[field_name] = field_nc_type.json_to_value(json_value[field_name])
        return self._class(*kwargs)

    @override
    def _value_to_json(self, value: D) -> NCType.Json:
        return {
            field_name: field_nc_type.value_to_json(getattr(value, field_name))
            for field_name, field_nc_type in self._fields.items()
        }
