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

from dataclasses import dataclass, field
from enum import StrEnum, auto, unique
from typing import Any, Self, TypeAlias

from typing_extensions import Literal, assert_never

from hathor.nanocontracts.types import BlueprintId, ContractId, TokenUid, VertexId
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
    type: Literal[IndexRecordType.CREATE_CONTRACT] = field(default=IndexRecordType.CREATE_CONTRACT, init=False)
    blueprint_id: BlueprintId
    contract_id: ContractId

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.CREATE_CONTRACT

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=IndexRecordType.CREATE_CONTRACT,
            blueprint_id=self.blueprint_id.hex(),
            contract_id=self.contract_id.hex(),
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        return cls(
            contract_id=ContractId(VertexId(bytes.fromhex(json_dict['contract_id']))),
            blueprint_id=BlueprintId(VertexId(bytes.fromhex(json_dict['blueprint_id']))),
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class CreateTokenRecord:
    """Record for token creation."""
    type: Literal[IndexRecordType.CREATE_TOKEN] = field(default=IndexRecordType.CREATE_TOKEN, init=False)
    token_uid: TokenUid
    amount: int
    token_symbol: str
    token_name: str
    token_version: Literal[TokenVersion.DEPOSIT] | Literal[TokenVersion.FEE]

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.CREATE_TOKEN
        assert self.token_version in (TokenVersion.DEPOSIT, TokenVersion.FEE)
        assert self.amount > 0

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=self.type,
            token_uid=self.token_uid.hex(),
            amount=self.amount,
            token_name=self.token_name,
            token_symbol=self.token_symbol,
            token_version=self.token_version,
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        token_version = TokenVersion(json_dict['token_version'])
        assert token_version in (TokenVersion.DEPOSIT, TokenVersion.FEE)
        return cls(
            token_uid=TokenUid(VertexId(bytes.fromhex(json_dict['token_uid']))),
            amount=json_dict['amount'],
            token_version=token_version,  # type: ignore[arg-type]
            token_name=json_dict['token_name'],
            token_symbol=json_dict['token_symbol'],
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class UpdateTokenBalanceRecord:
    """Record for token balance updates."""
    type: Literal[IndexRecordType.UPDATE_TOKEN_BALANCE] = field(
        default=IndexRecordType.UPDATE_TOKEN_BALANCE,
        init=False,
    )
    token_uid: TokenUid
    amount: int

    def __post_init__(self) -> None:
        assert self.type == IndexRecordType.UPDATE_TOKEN_BALANCE

    def to_json(self) -> dict[str, Any]:
        return dict(type=self.type, token_uid=self.token_uid.hex(), amount=self.amount)

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        return cls(
            token_uid=TokenUid(VertexId(bytes.fromhex(json_dict['token_uid']))),
            amount=json_dict['amount'],
        )


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

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=self.type,
            token_uid=self.token_uid.hex(),
            mint=self.mint,
            melt=self.melt,
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        type_ = IndexRecordType(json_dict['type'])
        assert type_ in (IndexRecordType.GRANT_AUTHORITIES, IndexRecordType.REVOKE_AUTHORITIES)
        return cls(
            token_uid=TokenUid(VertexId(bytes.fromhex(json_dict['token_uid']))),
            type=type_,  # type: ignore[arg-type]
            mint=json_dict['mint'],
            melt=json_dict['melt'],
        )


NCIndexUpdateRecord: TypeAlias = (
    CreateContractRecord
    | CreateTokenRecord
    | UpdateTokenBalanceRecord
    | UpdateAuthoritiesRecord
)


def nc_index_update_record_from_json(json_dict: dict[str, Any]) -> NCIndexUpdateRecord:
    record_type = IndexRecordType(json_dict['type'])
    match record_type:
        case IndexRecordType.CREATE_CONTRACT:
            return CreateContractRecord.from_json(json_dict)
        case IndexRecordType.CREATE_TOKEN:
            return CreateTokenRecord.from_json(json_dict)
        case IndexRecordType.UPDATE_TOKEN_BALANCE:
            return UpdateTokenBalanceRecord.from_json(json_dict)
        case IndexRecordType.GRANT_AUTHORITIES | IndexRecordType.REVOKE_AUTHORITIES:
            return UpdateAuthoritiesRecord.from_json(json_dict)
        case _:
            assert_never(record_type)
