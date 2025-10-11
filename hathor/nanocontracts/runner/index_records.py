#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto, unique
from typing import Any, TypeAlias

from typing_extensions import Literal, assert_never

from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.nc_types.dataclass_nc_type import make_dataclass_nc_type
from hathor.nanocontracts.types import BlueprintId, ContractId, TokenUid
from hathor.transaction.token_info import TokenVersion


@unique
class IndexRecordType(StrEnum):
    CREATE_CONTRACT = auto()
    CREATE_TOKEN = auto()
    UPDATE_TOKEN_BALANCE = auto()
    GRANT_AUTHORITIES = auto()
    REVOKE_AUTHORITIES = auto()


@dataclass(slots=True, frozen=True, kw_only=True)
class CreateContractRecord:
    """Record for contract creation."""
    type: Literal[IndexRecordType.CREATE_CONTRACT]
    blueprint_id: BlueprintId
    contract_id: ContractId

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.CREATE_CONTRACT


@dataclass(slots=True, frozen=True, kw_only=True)
class CreateTokenRecord:
    """Record for token creation."""
    type: Literal[IndexRecordType.CREATE_TOKEN]
    token_uid: TokenUid
    amount: int
    token_symbol: str
    token_name: str
    token_version: Literal[TokenVersion.DEPOSIT] | Literal[TokenVersion.FEE]

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.CREATE_TOKEN
        assert self.token_version in (TokenVersion.DEPOSIT, TokenVersion.FEE)
        assert self.amount > 0


@dataclass(slots=True, frozen=True, kw_only=True)
class UpdateTokenBalanceRecord:
    """Record for token balance updates."""
    type: Literal[IndexRecordType.UPDATE_TOKEN_BALANCE]
    token_uid: TokenUid
    amount: int

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.UPDATE_TOKEN_BALANCE


@dataclass(slots=True, frozen=True, kw_only=True)
class UpdateAuthoritiesRecord:
    """Record for token authority updates."""
    type: Literal[IndexRecordType.GRANT_AUTHORITIES] | Literal[IndexRecordType.REVOKE_AUTHORITIES]
    token_uid: TokenUid
    mint: bool
    melt: bool

    def __post_init__(self) -> None:
        assert self.type in (IndexRecordType.GRANT_AUTHORITIES, IndexRecordType.REVOKE_AUTHORITIES)
        assert self.mint or self.melt


NCIndexUpdateRecord: TypeAlias = (
    CreateContractRecord | CreateTokenRecord | UpdateTokenBalanceRecord | UpdateAuthoritiesRecord
)

CreateContractRecordNCType = make_dataclass_nc_type(CreateContractRecord)
CreateTokenRecordNCType = make_dataclass_nc_type(CreateTokenRecord)
UpdateTokenBalanceRecordNCType = make_dataclass_nc_type(UpdateTokenBalanceRecord)
UpdateAuthoritiesRecordNCType = make_dataclass_nc_type(UpdateAuthoritiesRecord)


def _get_nc_type(record_type: IndexRecordType) -> NCType:
    match record_type:
        case IndexRecordType.CREATE_CONTRACT:
            return CreateContractRecordNCType
        case IndexRecordType.CREATE_TOKEN:
            return CreateTokenRecordNCType
        case IndexRecordType.UPDATE_TOKEN_BALANCE:
            return UpdateTokenBalanceRecordNCType
        case IndexRecordType.GRANT_AUTHORITIES | IndexRecordType.REVOKE_AUTHORITIES:
            return UpdateAuthoritiesRecordNCType
        case _:
            assert_never(record_type)


def nc_index_update_record_from_json(json_dict: dict[str, Any]) -> NCIndexUpdateRecord:
    record_type = IndexRecordType(json_dict['type'])
    nc_type = _get_nc_type(record_type)
    return nc_type.json_to_value(json_dict)


def nc_index_update_record_to_json(record: NCIndexUpdateRecord) -> dict:
    nc_type = _get_nc_type(record.type)
    return nc_type.value_to_json(record)
