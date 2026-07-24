# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import OrderedDict, deque
from typing import TypeVar

from typing_extensions import assert_never

from hathorlib.nanocontracts.fields.container import TypeToContainerMap
from hathorlib.nanocontracts.fields.deque_container import DequeContainer
from hathorlib.nanocontracts.fields.dict_container import DictContainer
from hathorlib.nanocontracts.fields.field import Field
from hathorlib.nanocontracts.fields.set_container import SetContainer
from hathorlib.nanocontracts.nc_types import ESSENTIAL_TYPE_ALIAS_MAP, FIELD_TYPE_TO_NC_TYPE_MAP, TypeToNCTypeMap

__all__ = [
    'TYPE_TO_CONTAINER_MAP',
    'DequeContainer',
    'DictContainer',
    'Field',
    'SetContainer',
    'get_storage_token_amount_version',
    'make_field_for_type',
    'update_type_map',
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

FORCE_LEGACY_FIELDS: bool = False


def get_storage_token_amount_version() -> TokenAmountVersion:
    """Return the token amount version used for field storage (de)serialization.

    Storage serialization is global: every contract's trie data uses the same encodings, regardless of the
    contract's own token amount version, which only governs runtime behavior such as argument and return
    value serialization. `FORCE_LEGACY_FIELDS` switches the whole storage layer to the legacy V1 encodings,
    and is used only in tests, to ensure the migration works.
    """
    return TokenAmountVersion.V1 if FORCE_LEGACY_FIELDS else TokenAmountVersion.V2


def make_field_for_type(name: str, type_: type[T]) -> Field[T]:
    """ Like Field.from_name_and_type, but with default maps for every `TokenAmountVersion`.

    The field carries one serialization map per version; `get_storage_token_amount_version` selects
    which one is used at access time.
    """
    type_maps: dict[TokenAmountVersion, Field.TypeMap] = {}
    for version in TokenAmountVersion:
        type_nc_type_map = FIELD_TYPE_TO_NC_TYPE_MAP.copy()
        update_type_map(type_nc_type_map, version)
        type_maps[version] = Field.TypeMap(ESSENTIAL_TYPE_ALIAS_MAP, type_nc_type_map, TYPE_TO_CONTAINER_MAP)
    return Field.from_name_and_type(name, type_, type_maps=type_maps)


def update_type_map(type_map: TypeToNCTypeMap, token_amount_version: TokenAmountVersion) -> None:
    """Adjust the version-dependent NCTypes in `type_map` to the given token amount version."""
    from hathorlib.nanocontracts.nc_types import (
        Int32NCType,
        SignedDataNCType,
        SignedDataV2NCType,
        Uint32NCType,
        VarInt32NCType,
        VarUint32NCType,
    )
    from hathorlib.nanocontracts.types import Amount, SignedData
    match token_amount_version:
        case TokenAmountVersion.V1:
            assert type_map[int] is VarInt32NCType
            assert type_map[Amount] is VarUint32NCType
            assert type_map[SignedData] is SignedDataNCType
        case TokenAmountVersion.V2:
            # TODO: Use LPE
            type_map[int] = Int32NCType
            type_map[Amount] = Uint32NCType
            type_map[SignedData] = SignedDataV2NCType
        case _:
            assert_never(token_amount_version)
