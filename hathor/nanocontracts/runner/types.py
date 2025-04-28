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

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCNumberOfCallsExceeded, NCRecursionError
from hathor.nanocontracts.storage import NCChangesTracker, NCStorage
from hathor.nanocontracts.types import ContractId

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger


class CallType(str, Enum):
    PUBLIC = 'public'
    VIEW = 'view'


@dataclass(slots=True, frozen=True, kw_only=True)
class CallRecord:
    """This object keeps information about a single call between contracts."""

    # The type of the method being called (public or private).
    type: CallType

    # The depth in the call stack.
    depth: int

    # The contract being invoked.
    nanocontract_id: ContractId

    # The method being invoked.
    method_name: str

    # The context passed in this call.
    ctx: Context | None

    # The args and kwargs provided to the method.
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    # Keep track of all changes made by this call.
    changes_tracker: NCChangesTracker


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
    change_trackers: defaultdict[ContractId, list[NCChangesTracker]] = field(default_factory=lambda: defaultdict(list))

    # Flag to enable/disable keeping record of all calls.
    enable_call_trace: bool

    # A trace of the calls that happened. This will only be filled if `enable_call_trace` is true.
    calls: list[CallRecord] | None = None

    # Current depth of execution. This is a dynamic value that changes as the execution progresses.
    depth: int = 0

    # Counter of the number of calls performed so far. This is a dynamic value that changes as the
    # execution progresses.
    call_counter: int = 0

    # The logger to keep track of log entries during this call.
    nc_logger: NCLogger

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

        self.change_trackers[call_record.nanocontract_id].append(call_record.changes_tracker)

        assert self.depth == len(self.stack)
        self.call_counter += 1
        self.depth += 1
        self.stack.append(call_record)
        self.nc_logger.__log_call_begin__(call_record)

    def post_call(self, call_record: CallRecord) -> None:
        """Called after a call is finished."""
        assert call_record == self.stack.pop()
        assert call_record.changes_tracker == self.change_trackers[call_record.nanocontract_id][-1]
        assert call_record.changes_tracker.nc_id == call_record.changes_tracker.storage.nc_id
        self.depth -= 1

        change_trackers = self.change_trackers[call_record.nanocontract_id]
        if len(change_trackers) > 1:
            assert call_record.changes_tracker.storage == change_trackers[-2]
            assert call_record.changes_tracker == change_trackers.pop()
        else:
            assert type(call_record.changes_tracker.storage) is NCStorage
        self.nc_logger.__log_call_end__()
