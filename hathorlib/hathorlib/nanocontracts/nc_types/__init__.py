# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import OrderedDict, deque
from types import NoneType, UnionType
from typing import NamedTuple, TypeVar, Union

from typing_extensions import assert_never

from hathorlib.nanocontracts.nc_types.address_nc_type import AddressNCType
from hathorlib.nanocontracts.nc_types.bool_nc_type import BoolNCType
from hathorlib.nanocontracts.nc_types.bytes_nc_type import BytesLikeNCType, BytesNCType
from hathorlib.nanocontracts.nc_types.caller_id_nc_type import CallerIdNCType
from hathorlib.nanocontracts.nc_types.collection_nc_type import DequeNCType, FrozenSetNCType, ListNCType, SetNCType
from hathorlib.nanocontracts.nc_types.dataclass_nc_type import DataclassNCType
from hathorlib.nanocontracts.nc_types.fixed_size_bytes_nc_type import Bytes32NCType
from hathorlib.nanocontracts.nc_types.map_nc_type import DictNCType
from hathorlib.nanocontracts.nc_types.namedtuple_nc_type import NamedTupleNCType
from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.nanocontracts.nc_types.null_nc_type import NullNCType
from hathorlib.nanocontracts.nc_types.optional_nc_type import OptionalNCType
from hathorlib.nanocontracts.nc_types.signed_data_nc_type import SignedDataNCType
from hathorlib.nanocontracts.nc_types.sized_int_nc_type import Int32NCType, Uint32NCType
from hathorlib.nanocontracts.nc_types.str_nc_type import StrNCType
from hathorlib.nanocontracts.nc_types.token_uid_nc_type import TokenUidNCType
from hathorlib.nanocontracts.nc_types.tuple_nc_type import TupleNCType
from hathorlib.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap
from hathorlib.nanocontracts.nc_types.varint_nc_type import (
    VarInt32NCType,
    VarInt32V2NCType,
    VarUint32NCType,
    VarUint32V2NCType,
)
from hathorlib.nanocontracts.storage_version import get_storage_token_amount_version
from hathorlib.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    SignedDataV1,
    SignedDataV2,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
)

__all__ = [
    'ARG_TYPE_TO_NC_TYPE_MAP',
    'DEFAULT_TYPE_ALIAS_MAP',
    'ESSENTIAL_TYPE_ALIAS_MAP',
    'FIELD_TYPE_TO_NC_TYPE_MAP',
    'RETURN_TYPE_TO_NC_TYPE_MAP',
    'AddressNCType',
    'BoolNCType',
    'BytesLikeNCType',
    'BytesNCType',
    'CallerIdNCType',
    'DataclassNCType',
    'DequeNCType',
    'DictNCType',
    'FrozenSetNCType',
    'Int32NCType',
    'ListNCType',
    'NCType',
    'NamedTupleNCType',
    'NullNCType',
    'OptionalNCType',
    'SetNCType',
    'SignedDataNCType',
    'StrNCType',
    'TupleNCType',
    'TypeAliasMap',
    'TypeToNCTypeMap',
    'Uint32NCType',
    'VarInt32NCType',
    'VarInt32V2NCType',
    'VarUint32NCType',
    'VarUint32V2NCType',
    'make_nc_type_for_field_type',
    'make_nc_type_for_arg_type',
    'make_nc_type_for_return_type',
    'make_versioned_nc_type_map',
]

from hathorlib.token_amount_version import TokenAmountVersion

T = TypeVar('T')

# this is the minimum type-alias-map needed for everything to work as intended
ESSENTIAL_TYPE_ALIAS_MAP: TypeAliasMap = {
    # XXX: technically types.UnionType is not a type, so mypy complains, but for our purposes it is a type
    Union: UnionType,  # type: ignore[dict-item]
}

# when used inside fields these must emit a warning, because an immutable variant is provided instead, if the mutable
# variant was provided the mutability would not be tracked
DEFAULT_TYPE_ALIAS_MAP: TypeAliasMap = {
    **ESSENTIAL_TYPE_ALIAS_MAP,
    OrderedDict: dict,
    bytearray: bytes,
    # deque: tuple,  # I think this is too much
    list: tuple,
    set: frozenset,
}

# Mapping between types and NCType classes.
FIELD_TYPE_TO_NC_TYPE_MAP: TypeToNCTypeMap = {
    # builtin types:
    bool: BoolNCType,
    bytes: BytesNCType,
    frozenset: FrozenSetNCType,
    int: VarInt32NCType,
    str: StrNCType,
    tuple: TupleNCType,
    # other Python types:
    # XXX: ignored dict-item because Union is not considered a type, so mypy fails it, but it works for our case
    Union: OptionalNCType,  # type: ignore[dict-item]
    UnionType: OptionalNCType,
    NamedTuple: NamedTupleNCType,
    # hathor types:
    Address: AddressNCType,
    Amount: VarUint32NCType,
    BlueprintId: Bytes32NCType,
    ContractId: Bytes32NCType,
    Timestamp: Uint32NCType,
    TokenUid: TokenUidNCType,
    TxOutputScript: BytesLikeNCType[TxOutputScript],
    VertexId: Bytes32NCType,
    # XXX: the version-abstract `SignedData` base is intentionally not mapped: annotations must name a
    #      concrete class, which pins the payload-signing version under any map. Blueprint code names
    #      `SignedData` and gets the concrete class for its version through the routed imports.
    SignedDataV1: SignedDataNCType,
    SignedDataV2: SignedDataNCType,
    (Address, ContractId): CallerIdNCType,
}

# This mapping includes all supported NCType classes, should only be used for parsing function calls
ARG_TYPE_TO_NC_TYPE_MAP: TypeToNCTypeMap = {
    **FIELD_TYPE_TO_NC_TYPE_MAP,
    # bultin types:
    dict: DictNCType,
    list: ListNCType,
    set: SetNCType,
    # other Python types:
    deque: DequeNCType,
    OrderedDict: DictNCType,
}

RETURN_TYPE_TO_NC_TYPE_MAP: TypeToNCTypeMap = {
    **ARG_TYPE_TO_NC_TYPE_MAP,
    # XXX: ignored dict-item because technically None is not a type, type[None]/NoneType is
    None: NullNCType,  # type: ignore[dict-item]
    NoneType: NullNCType,  # this can come up here as well as None
}


def make_versioned_nc_type_map(
    nc_type_map: TypeToNCTypeMap,
    token_amount_version: TokenAmountVersion,
) -> TypeToNCTypeMap:
    """Return a copy of `nc_type_map` with its version-dependent NCTypes set to `token_amount_version`.

    Only the version-abstract `int` and `Amount` keys are swapped. `SignedData` annotations name a
    concrete versioned class, which is annotation-faithful and identical in every map.
    """
    versioned_map = nc_type_map.copy()
    match token_amount_version:
        case TokenAmountVersion.V1:
            assert versioned_map[int] is VarInt32NCType
            assert versioned_map[Amount] is VarUint32NCType
        case TokenAmountVersion.V2:
            versioned_map[int] = VarInt32V2NCType
            versioned_map[Amount] = VarUint32V2NCType
        case _:
            assert_never(token_amount_version)
    return versioned_map


def _build_type_maps(
    alias_map: TypeAliasMap,
    nc_type_map: TypeToNCTypeMap,
) -> dict[TokenAmountVersion, NCType.TypeMap]:
    """Build one `TypeMap` per token amount version; the maps depend only on the version, so they are shared."""
    return {
        version: NCType.TypeMap(alias_map, make_versioned_nc_type_map(nc_type_map, version))
        for version in TokenAmountVersion
    }


# Per-version type maps, built once and reused; `NCType.from_type` does not mutate the map it is given.
_FIELD_TYPE_MAPS = _build_type_maps(DEFAULT_TYPE_ALIAS_MAP, FIELD_TYPE_TO_NC_TYPE_MAP)
_ARG_TYPE_MAPS = _build_type_maps(ESSENTIAL_TYPE_ALIAS_MAP, ARG_TYPE_TO_NC_TYPE_MAP)
_RETURN_TYPE_MAPS = _build_type_maps(ESSENTIAL_TYPE_ALIAS_MAP, RETURN_TYPE_TO_NC_TYPE_MAP)


def make_nc_type_for_field_type(type_: type[T], /) -> NCType[T]:
    """ Like NCType.from_type, but with maps for field annotations.

    Uses the storage serialization version from `get_storage_token_amount_version`, which is global
    and independent of any contract's token amount version.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_FIELD_TYPE_MAPS[get_storage_token_amount_version()])


def make_nc_type_for_arg_type(type_: type[T], /, token_amount_version: TokenAmountVersion) -> NCType[T]:
    """ Like NCType.from_type, but with maps for function arg annotations.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_ARG_TYPE_MAPS[token_amount_version])


def make_nc_type_for_return_type(type_: type[T], /, token_amount_version: TokenAmountVersion) -> NCType[T]:
    """ Like NCType.from_type, but with maps for function return annotations.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_RETURN_TYPE_MAPS[token_amount_version])
