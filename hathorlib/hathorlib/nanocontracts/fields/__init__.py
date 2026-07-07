# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import OrderedDict, deque
from typing import TypeVar

from hathorlib.nanocontracts.fields.container import TypeToContainerMap
from hathorlib.nanocontracts.fields.deque_container import DequeContainer
from hathorlib.nanocontracts.fields.dict_container import DictContainer
from hathorlib.nanocontracts.fields.field import Field
from hathorlib.nanocontracts.fields.set_container import SetContainer
from hathorlib.nanocontracts.nc_types import ESSENTIAL_TYPE_ALIAS_MAP, FIELD_TYPE_TO_NC_TYPE_MAP
from hathorlib.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap

__all__ = [
    'TYPE_TO_CONTAINER_MAP',
    'DequeContainer',
    'DictContainer',
    'Field',
    'SetContainer',
    'make_field_for_type',
]

T = TypeVar('T')

TYPE_TO_CONTAINER_MAP: TypeToContainerMap = {
    deque: DequeContainer,
    dict: DictContainer,
    OrderedDict: DictContainer,
    list: DequeContainer,  # XXX: we should really make a ListField, a deque is different from a list
    set: SetContainer,
}


def make_field_for_type(
    name: str,
    type_: type[T],
    /,
    *,
    type_alias_map: TypeAliasMap = ESSENTIAL_TYPE_ALIAS_MAP,
    type_nc_type_map: TypeToNCTypeMap = FIELD_TYPE_TO_NC_TYPE_MAP,
    type_container_map: TypeToContainerMap = TYPE_TO_CONTAINER_MAP,
) -> Field[T]:
    """ Like Field.from_name_and_type, but with default maps.

    Default arguments can't be easily added to NCType.from_type signature because of recursion.
    """
    type_map = Field.TypeMap(type_alias_map, type_nc_type_map, type_container_map)
    return Field.from_name_and_type(name, type_, type_map=type_map)
