# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import OrderedDict, deque
from typing import TypeVar

from hathorlib.nanocontracts.fields.container import TypeToContainerMap
from hathorlib.nanocontracts.fields.deque_container import DequeContainer
from hathorlib.nanocontracts.fields.dict_container import DictContainer
from hathorlib.nanocontracts.fields.field import Field
from hathorlib.nanocontracts.fields.set_container import SetContainer
from hathorlib.nanocontracts.nc_types import (
    ESSENTIAL_TYPE_ALIAS_MAP,
    FIELD_TYPE_TO_NC_TYPE_MAP,
    make_versioned_nc_type_map,
)

__all__ = [
    'TYPE_TO_CONTAINER_MAP',
    'DequeContainer',
    'DictContainer',
    'Field',
    'SetContainer',
    'make_field_for_type',
]

from hathorlib.token_amount_version import TokenAmountVersion

T = TypeVar('T')

TYPE_TO_CONTAINER_MAP: TypeToContainerMap = {
    deque: DequeContainer,
    dict: DictContainer,
    OrderedDict: DictContainer,
    list: DequeContainer,  # XXX: we should really make a ListField, a deque is different from a list
    set: SetContainer,
}


def make_field_for_type(name: str, type_: type[T]) -> Field[T]:
    """ Like Field.from_name_and_type, but with default maps for every `TokenAmountVersion`.

    The field carries one serialization map per version; `get_storage_token_amount_version` selects
    which one is used at access time.
    """
    return Field.from_name_and_type(name, type_, type_maps=_FIELD_TYPE_MAPS)


def _build_field_type_maps() -> dict[TokenAmountVersion, Field.TypeMap]:
    """Build the per-version field serialization maps once, shared by every field.

    The maps depend only on the token amount version, not on the field name or type, so a field only
    needs to select the right one at access time via `get_storage_token_amount_version`.
    """
    return {
        version: Field.TypeMap(
            ESSENTIAL_TYPE_ALIAS_MAP,
            make_versioned_nc_type_map(FIELD_TYPE_TO_NC_TYPE_MAP, version),
            TYPE_TO_CONTAINER_MAP,
        )
        for version in TokenAmountVersion
    }


_FIELD_TYPE_MAPS: dict[TokenAmountVersion, Field.TypeMap] = _build_field_type_maps()
