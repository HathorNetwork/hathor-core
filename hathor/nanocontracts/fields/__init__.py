# Copyright 2023 Hathor Labs
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

from collections import deque
from typing import TypeVar

from hathor.nanocontracts.fields.deque_field import DequeField
from hathor.nanocontracts.fields.dict_field import DictField
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.fields.set_field import SetField
from hathor.nanocontracts.fields.utils import TypeToFieldMap
from hathor.nanocontracts.nc_types import DEFAULT_TYPE_ALIAS_MAP, DEFAULT_TYPE_TO_NC_TYPE_MAP
from hathor.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap

__all__ = [
    'DEFAULT_TYPE_TO_FIELD_MAP',
    'DequeField',
    'DictField',
    'Field',
    'SetField',
    'TypeToFieldMap',
    'make_field_for_type',
]

T = TypeVar('T')

DEFAULT_TYPE_TO_FIELD_MAP: TypeToFieldMap = {
    dict: DictField,
    list: DequeField,  # XXX: we should really make a ListField, a deque is different from a list
    set: SetField,
    deque: DequeField,
    # XXX: other types fallback to DEFAULT_TYPE_TO_NC_TYPE_MAP
}


def make_field_for_type(
    name: str,
    type_: type[T],
    /,
    *,
    type_field_map: TypeToFieldMap = DEFAULT_TYPE_TO_FIELD_MAP,
    type_nc_type_map: TypeToNCTypeMap = DEFAULT_TYPE_TO_NC_TYPE_MAP,
    type_alias_map: TypeAliasMap = DEFAULT_TYPE_ALIAS_MAP,
) -> Field[T]:
    """ Like Field.from_name_and_type, but with default maps.

    Default arguments can't be easily added to NCType.from_type signature because of recursion.
    """
    type_map = Field.TypeMap(type_alias_map, type_nc_type_map, type_field_map)
    return Field.from_name_and_type(name, type_, type_map=type_map)
