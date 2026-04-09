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

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum, auto, unique
from typing import TYPE_CHECKING, Any, Literal

from pydantic import ConfigDict, Field, field_serializer, field_validator
from typing_extensions import override

from hathorlib.nanocontracts.clock import ClockProtocol
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.runner.call_info import CallType
from hathorlib.nanocontracts.types import ContractId
from hathorlib.utils.pydantic import BaseModel, Hex

if TYPE_CHECKING:
    from hathorlib.nanocontracts.runner.call_info import CallInfo, CallRecord

MAX_EVENT_SIZE: int = 1024  # 1KiB


@unique
class NCLogConfig(StrEnum):
    # Don't save any nano contract logs.
    NONE = auto()

    # Save logs for all nano contracts.
    ALL = auto()

    # Only save logs for nano contracts that failed.
    FAILED = auto()

    # Only save logs for nano contracts that failed with an unhandled exception (that is, not NCFail).
    FAILED_UNHANDLED = auto()


@unique
class NCLogLevel(IntEnum):
    """The log level of NC execution logs."""
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3

    @staticmethod
    def from_str(value: str) -> NCLogLevel | None:
        """Create a NCLogLevel from a string, or return None if it's invalid."""
        try:
            return NCLogLevel[value]
        except KeyError:
            return None


class _BaseNCEntry(BaseModel):
    type: str
    level: NCLogLevel
    timestamp: float

    @field_serializer('level')
    @classmethod
    def _serialize_level(cls, level: NCLogLevel) -> str:
        return level.name

    @field_validator('level', mode='before')
    @classmethod
    def _parse_level(cls, level: NCLogLevel | int | str) -> NCLogLevel:
        if isinstance(level, NCLogLevel):
            return level
        if isinstance(level, int):
            return NCLogLevel(level)
        if isinstance(level, str):
            return NCLogLevel[level]
        raise TypeError(f'invalid level type: {type(level)}')


class NCLogEntry(_BaseNCEntry):
    """An entry representing a single log in a NC execution."""
    type: Literal['LOG'] = 'LOG'
    message: str
    key_values: dict[str, str] = Field(default_factory=dict)


class NCCallBeginEntry(_BaseNCEntry):
    """An entry representing a single method call beginning in a NC execution."""
    type: Literal['CALL_BEGIN'] = 'CALL_BEGIN'
    level: Literal[NCLogLevel.DEBUG] = NCLogLevel.DEBUG
    nc_id: Hex[ContractId]
    call_type: CallType
    method_name: str
    str_args: str = '()'
    actions: list[dict[str, Any]] | None

    @staticmethod
    def from_call_record(call_record: CallRecord, *, timestamp: float) -> NCCallBeginEntry:
        """Create a NCCallEntry from a CallRecord."""
        actions = None
        if call_record.ctx is not None:
            ctx_json = call_record.ctx.to_json()
            actions = ctx_json['actions']

        return NCCallBeginEntry(
            nc_id=call_record.contract_id,
            call_type=call_record.type,
            method_name=call_record.method_name,
            str_args=str(call_record.args),
            timestamp=timestamp,
            actions=actions
        )


class NCCallEndEntry(_BaseNCEntry):
    """An entry representing a single method call ending in a NC execution."""
    type: Literal['CALL_END'] = 'CALL_END'
    level: Literal[NCLogLevel.DEBUG] = NCLogLevel.DEBUG


class NCExecEntry(BaseModel):
    """
    An entry representing the whole execution of a NC.
    It may contain several calls across different NCs, with logs in order.
    """
    logs: list[NCCallBeginEntry | NCLogEntry | NCCallEndEntry]
    error_traceback: str | None = None

    @staticmethod
    def from_call_info(call_info: CallInfo, error_tb: str | None) -> NCExecEntry:
        """Create a NCExecEntry from a CallInfo and an optional traceback."""
        return NCExecEntry(
            logs=call_info.nc_logger.__entries__,
            error_traceback=error_tb,
        )

    def filter(self, log_level: NCLogLevel) -> NCExecEntry:
        """Create a new NCExecEntry while keeping logs with the provided log level or higher."""
        return self.model_copy(
            update=dict(
                logs=[log for log in self.logs if log.level >= log_level],
            ),
        )


class NCExecEntries(BaseModel):
    """
    A mapping of block IDs to lists of NC executions.
    If there are reorgs, a single block can execute the same NC more than once.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # VertexId => logs (list[NCExecEntry])
    entries: dict[bytes, list[NCExecEntry]]

    @staticmethod
    def from_json(json_dict: dict[str, Any]) -> NCExecEntries:
        entries = {
            bytes.fromhex(block_id_hex): [NCExecEntry.model_validate(entry) for entry in entries]
            for block_id_hex, entries in json_dict.items()
        }
        return NCExecEntries(entries=entries)

    @override
    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            block_id.hex(): [entry.model_dump(*args, **kwargs) for entry in block_entries]
            for block_id, block_entries in self.entries.items()
        }


@dataclass(slots=True, frozen=True, kw_only=True)
class NCEvent:
    nc_id: ContractId
    data: bytes


# TODO: Rename to something else now that it has events? move events out of it?
@dataclass(slots=True)
class NCLogger:
    """
    A dataclass that provides instrumentation-related features, including logging-equivalent functionality
    saving log entries in memory, and emission of events.
    To be used inside Blueprints.
    """
    __reactor__: ClockProtocol
    __nc_id__: ContractId
    __entries__: list[NCCallBeginEntry | NCLogEntry | NCCallEndEntry] = field(default_factory=list)
    __events__: list[NCEvent] = field(default_factory=list)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Create a new DEBUG log entry."""
        self.__log__(NCLogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Create a new INFO log entry."""
        self.__log__(NCLogLevel.INFO, message, **kwargs)

    def warn(self, message: str, **kwargs: Any) -> None:
        """Create a new WARN log entry."""
        self.__log__(NCLogLevel.WARN, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Create a new ERROR log entry."""
        self.__log__(NCLogLevel.ERROR, message, **kwargs)

    def __emit_event__(self, data: bytes) -> None:
        """Emit a custom event from a Nano Contract."""
        if not isinstance(data, bytes):
            raise NCFail(f'event data must be of type `bytes`, found `{type(data).__name__}`')
        if len(data) > MAX_EVENT_SIZE:
            raise NCFail(f'event data cannot be larger than {MAX_EVENT_SIZE} bytes, is {len(data)}')
        self.__events__.append(NCEvent(nc_id=self.__nc_id__, data=data))

    def __log__(self, level: NCLogLevel, message: str, **kwargs: Any) -> None:
        """Create a new log entry."""
        key_values = {k: v.hex() if isinstance(v, bytes) else str(v) for k, v in kwargs.items()}
        entry = NCLogEntry(level=level, message=message, key_values=key_values, timestamp=self.__reactor__.seconds())
        self.__entries__.append(entry)

    def __log_call_begin__(self, call_record: CallRecord) -> None:
        """Log the beginning of a call."""
        self.__entries__.append(NCCallBeginEntry.from_call_record(call_record, timestamp=self.__reactor__.seconds()))

    def __log_call_end__(self) -> None:
        """Log the end of a call."""
        self.__entries__.append(NCCallEndEntry(timestamp=self.__reactor__.seconds()))


NC_EXEC_LOGS_DIR = 'nc_exec_logs'
