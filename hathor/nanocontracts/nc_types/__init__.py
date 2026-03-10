# Copyright 2025 Hathor Labs
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

# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.nc_types import *  # noqa: F401,F403
from hathorlib.nanocontracts.nc_types import (  # noqa: F401
    ARG_TYPE_TO_NC_TYPE_MAP,
    DEFAULT_TYPE_ALIAS_MAP,
    ESSENTIAL_TYPE_ALIAS_MAP,
    FIELD_TYPE_TO_NC_TYPE_MAP,
    RETURN_TYPE_TO_NC_TYPE_MAP,
    AddressNCType,
    BoolNCType,
    Bytes32NCType,
    BytesLikeNCType,
    BytesNCType,
    CallerIdNCType,
    DataclassNCType,
    DequeNCType,
    DictNCType,
    FrozenSetNCType,
    Int32NCType,
    ListNCType,
    NamedTupleNCType,
    NCType,
    NullNCType,
    OptionalNCType,
    SetNCType,
    SignedDataNCType,
    StrNCType,
    TupleNCType,
    TypeAliasMap,
    TypeToNCTypeMap,
    Uint32NCType,
    VarInt32NCType,
    VarUint32NCType,
    make_nc_type_for_arg_type,
    make_nc_type_for_field_type,
    make_nc_type_for_return_type,
)
from hathorlib.nanocontracts.nc_types.token_uid_nc_type import TokenUidNCType  # noqa: F401
