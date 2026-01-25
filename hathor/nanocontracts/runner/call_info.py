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
from typing import TYPE_CHECKING, Any

from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCNumberOfCallsExceeded, NCRecursionError
from hathor.nanocontracts.runner.index_records import NCIndexUpdateRecord
from hathor.nanocontracts.sandbox import SandboxCounters, SandboxCounts
from hathor.nanocontracts.storage import NCChangesTracker, NCContractStorage
from hathor.nanocontracts.types import BlueprintId, ContractId

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger


@unique
class CallType(StrEnum):
    PUBLIC = auto()
    VIEW = auto()


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

    # Sandbox counters captured before/after this call. None when sandbox is not active.
    # This is a mutable container that gets populated during call execution.
    sandbox_counters: SandboxCounters | None = None

    # OCB loading cost charged for this call. None means no loading cost was charged
    # (either sandbox not active, or blueprint was already loaded in this call chain).
    # This is set when the blueprint is loaded for this call.
    ocb_loading_cost: SandboxCounts | None = None


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
        self.nc_logger.__log_call_end__(call_record)
