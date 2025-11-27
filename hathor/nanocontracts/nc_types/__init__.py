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

from collections import OrderedDict, deque
from types import NoneType, UnionType
from typing import NamedTuple, TypeVar, Union

from hathor.nanocontracts.nc_types.address_nc_type import AddressNCType
from hathor.nanocontracts.nc_types.bool_nc_type import BoolNCType
from hathor.nanocontracts.nc_types.bytes_nc_type import BytesLikeNCType, BytesNCType
from hathor.nanocontracts.nc_types.caller_id_nc_type import CallerIdNCType
from hathor.nanocontracts.nc_types.collection_nc_type import DequeNCType, FrozenSetNCType, ListNCType, SetNCType
from hathor.nanocontracts.nc_types.dataclass_nc_type import DataclassNCType
from hathor.nanocontracts.nc_types.fixed_size_bytes_nc_type import Bytes32NCType
from hathor.nanocontracts.nc_types.map_nc_type import DictNCType
from hathor.nanocontracts.nc_types.namedtuple_nc_type import NamedTupleNCType
from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.nc_types.null_nc_type import NullNCType
from hathor.nanocontracts.nc_types.optional_nc_type import OptionalNCType
from hathor.nanocontracts.nc_types.signed_data_nc_type import SignedDataNCType
from hathor.nanocontracts.nc_types.sized_int_nc_type import Int32NCType, Uint32NCType
from hathor.nanocontracts.nc_types.str_nc_type import StrNCType
from hathor.nanocontracts.nc_types.token_uid_nc_type import TokenUidNCType
from hathor.nanocontracts.nc_types.tuple_nc_type import TupleNCType
from hathor.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap
from hathor.nanocontracts.nc_types.varint_nc_type import VarInt32NCType, VarUint32NCType
from hathor.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    SignedData,
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
    'VarUint32NCType',
    'make_nc_type_for_field_type',
    'make_nc_type_for_arg_type',
    'make_nc_type_for_return_type',
]

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
    SignedData: SignedDataNCType,
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


_FIELD_TYPE_MAP = NCType.TypeMap(DEFAULT_TYPE_ALIAS_MAP, FIELD_TYPE_TO_NC_TYPE_MAP)


def make_nc_type_for_field_type(type_: type[T], /) -> NCType[T]:
    """ Like NCType.from_type, but with maps for field annotations.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_FIELD_TYPE_MAP)


_ARG_TYPE_MAP = NCType.TypeMap(ESSENTIAL_TYPE_ALIAS_MAP, ARG_TYPE_TO_NC_TYPE_MAP)


def make_nc_type_for_arg_type(type_: type[T], /) -> NCType[T]:
    """ Like NCType.from_type, but with maps for function arg annotations.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_ARG_TYPE_MAP)


_RETURN_TYPE_MAP = NCType.TypeMap(ESSENTIAL_TYPE_ALIAS_MAP, RETURN_TYPE_TO_NC_TYPE_MAP)


def make_nc_type_for_return_type(type_: type[T], /) -> NCType[T]:
    """ Like NCType.from_type, but with maps for function return annotations.

    If you need to customize the mapping use `NCType.from_type` instead.
    """
    return NCType.from_type(type_, type_map=_RETURN_TYPE_MAP)
