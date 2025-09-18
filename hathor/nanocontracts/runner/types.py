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

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto, unique
from typing import TYPE_CHECKING, Any, TypeAlias

from typing_extensions import Literal, Self, assert_never

from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCNumberOfCallsExceeded, NCRecursionError
from hathor.nanocontracts.storage import NCChangesTracker, NCContractStorage
from hathor.nanocontracts.types import BlueprintId, ContractId, TokenUid, VertexId
from hathor.transaction.token_info import TokenVersion

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger


@unique
class CallType(StrEnum):
    PUBLIC = auto()
    VIEW = auto()


@unique
class IndexUpdateRecordType(StrEnum):
    CREATE_CONTRACT = auto()
    MINT_TOKENS = auto()
    MELT_TOKENS = auto()
    CREATE_TOKEN = auto()
    UPDATE_AUTHORITIES = auto()


@dataclass(slots=True, frozen=True, kw_only=True)
class SyscallCreateContractRecord:
    blueprint_id: BlueprintId
    contract_id: ContractId

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=IndexUpdateRecordType.CREATE_CONTRACT,
            blueprint_id=self.blueprint_id.hex(),
            contract_id=self.contract_id.hex(),
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        assert json_dict['type'] == IndexUpdateRecordType.CREATE_CONTRACT
        return cls(
            contract_id=ContractId(VertexId(bytes.fromhex(json_dict['contract_id']))),
            blueprint_id=BlueprintId(VertexId(bytes.fromhex(json_dict['blueprint_id']))),
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class SyscallUpdateTokensRecord:
    type: (
        Literal[IndexUpdateRecordType.MINT_TOKENS]
        | Literal[IndexUpdateRecordType.MELT_TOKENS]
        | Literal[IndexUpdateRecordType.CREATE_TOKEN]
    )
    token_uid: TokenUid
    token_amount: int
    htr_amount: int
    token_symbol: str | None = None
    token_name: str | None = None
    token_version: TokenVersion | None = None

    def __post_init__(self) -> None:
        match self.type:
            case IndexUpdateRecordType.MINT_TOKENS | IndexUpdateRecordType.CREATE_TOKEN:
                assert self.token_amount > 0 and self.htr_amount < 0
            case IndexUpdateRecordType.MELT_TOKENS:
                assert self.token_amount < 0 and self.htr_amount > 0
            case _:
                assert_never(self.type)

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=self.type,
            token_uid=self.token_uid.hex(),
            token_amount=self.token_amount,
            token_version=self.token_version,
            htr_amount=self.htr_amount,
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        valid_types = (
            IndexUpdateRecordType.MINT_TOKENS, IndexUpdateRecordType.MINT_TOKENS, IndexUpdateRecordType.CREATE_TOKEN
        )
        assert json_dict['type'] in valid_types
        return cls(
            type=json_dict['type'],
            token_uid=TokenUid(VertexId(bytes.fromhex(json_dict['token_uid']))),
            token_amount=json_dict['token_amount'],
            token_version=json_dict['token_version'],
            htr_amount=json_dict['htr_amount'],
        )


@unique
class UpdateAuthoritiesRecordType(StrEnum):
    GRANT = auto()
    REVOKE = auto()


@dataclass(slots=True, frozen=True, kw_only=True)
class UpdateAuthoritiesRecord:
    token_uid: TokenUid
    sub_type: UpdateAuthoritiesRecordType
    mint: bool
    melt: bool

    def __post_init__(self) -> None:
        assert self.mint or self.melt

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=IndexUpdateRecordType.UPDATE_AUTHORITIES,
            token_uid=self.token_uid.hex(),
            sub_type=self.sub_type,
            mint=self.mint,
            melt=self.melt,
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        assert json_dict['type'] == IndexUpdateRecordType.UPDATE_AUTHORITIES
        return cls(
            token_uid=TokenUid(VertexId(bytes.fromhex(json_dict['token_uid']))),
            sub_type=UpdateAuthoritiesRecordType(json_dict['sub_type']),
            mint=json_dict['mint'],
            melt=json_dict['melt'],
        )


NCIndexUpdateRecord: TypeAlias = SyscallCreateContractRecord | SyscallUpdateTokensRecord | UpdateAuthoritiesRecord


def nc_index_update_record_from_json(json_dict: dict[str, Any]) -> NCIndexUpdateRecord:
    syscall_type = IndexUpdateRecordType(json_dict['type'])
    match syscall_type:
        case IndexUpdateRecordType.CREATE_CONTRACT:
            return SyscallCreateContractRecord.from_json(json_dict)
        case (
            IndexUpdateRecordType.MINT_TOKENS
            | IndexUpdateRecordType.MELT_TOKENS
            | IndexUpdateRecordType.CREATE_TOKEN
        ):
            return SyscallUpdateTokensRecord.from_json(json_dict)
        case IndexUpdateRecordType.UPDATE_AUTHORITIES:
            return UpdateAuthoritiesRecord.from_json(json_dict)
        case _:
            raise assert_never(f'invalid syscall record type: "{syscall_type}"')


@dataclass(slots=True, frozen=True, kw_only=True)
class CallRecord:
    """This object keeps information about a single call between contracts."""

    # The type of the method being called (public or private).
    type: CallType

    # The depth in the call stack.
    depth: int

    # The contract being invoked.
    contract_id: ContractId

    # The blueprint at the time of execution.
    blueprint_id: BlueprintId

    # The method being invoked.
    method_name: str

    # The context passed in this call.
    ctx: Context | None

    # The args provided to the method.
    args: tuple[Any, ...]

    # Keep track of all changes made by this call.
    changes_tracker: NCChangesTracker

    # A list of actions or syscalls that affect indexes. None when it's a VIEW call.
    index_updates: list[NCIndexUpdateRecord] | None


@dataclass(slots=True, kw_only=True)
class CallInfo:
    """This object keeps information about a method call and its subsequence calls."""
    MAX_RECURSION_DEPTH: int
    MAX_CALL_COUNTER: int

    # The execution stack. This stack is dynamic and changes as the execution progresses.
    stack: list[CallRecord] = field(default_factory=list)

    # Change trackers are grouped by contract. Because multiple calls can occur between contracts, leading to more than
    # one NCChangesTracker per contract, a stack is used. This design makes it fast to retrieve the most recent tracker
    # for a given contract whenever a new call is made.
    change_trackers: dict[ContractId, list[NCChangesTracker]] = field(default_factory=dict)

    # Flag to enable/disable keeping record of all calls.
    enable_call_trace: bool

    # A trace of the calls that happened. This will only be filled if `enable_call_trace` is true.
    calls: list[CallRecord] | None = None

    # Counter of the number of calls performed so far. This is a dynamic value that changes as the
    # execution progresses.
    call_counter: int = 0

    # The logger to keep track of log entries during this call.
    nc_logger: NCLogger

    @property
    def depth(self) -> int:
        """Get the depth of the call stack."""
        return len(self.stack)

    def pre_call(self, call_record: CallRecord) -> None:
        """Called before a new call is executed."""
        if self.depth >= self.MAX_RECURSION_DEPTH:
            raise NCRecursionError

        if self.call_counter >= self.MAX_CALL_COUNTER:
            raise NCNumberOfCallsExceeded

        if self.enable_call_trace:
            if self.calls is None:
                self.calls = []
            self.calls.append(call_record)

        if call_record.contract_id not in self.change_trackers:
            self.change_trackers[call_record.contract_id] = [call_record.changes_tracker]
        else:
            self.change_trackers[call_record.contract_id].append(call_record.changes_tracker)

        self.call_counter += 1
        self.stack.append(call_record)
        self.nc_logger.__log_call_begin__(call_record)

    def post_call(self, call_record: CallRecord) -> None:
        """Called after a call is finished."""
        assert call_record == self.stack.pop()
        assert call_record.changes_tracker == self.change_trackers[call_record.contract_id][-1]
        assert call_record.changes_tracker.nc_id == call_record.changes_tracker.storage.nc_id

        change_trackers = self.change_trackers[call_record.contract_id]
        if len(change_trackers) > 1:
            assert call_record.changes_tracker.storage == change_trackers[-2]
            assert call_record.changes_tracker == change_trackers.pop()
        else:
            assert type(call_record.changes_tracker.storage) is NCContractStorage
        self.nc_logger.__log_call_end__()
