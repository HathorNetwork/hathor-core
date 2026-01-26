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

import json
import os.path
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum, auto, unique
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, assert_never

from pydantic import Field, validator
from typing_extensions import override

from hathor.nanocontracts import NCFail
from hathor.nanocontracts.runner import CallInfo, CallRecord, CallType
from hathor.nanocontracts.types import ContractId
from hathor.reactor import ReactorProtocol
from hathor.transaction import Transaction
from hathor.types import VertexId
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings

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

    @override
    def dict(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        json_dict = super().dict(*args, **kwargs)
        json_dict['level'] = self.level.name
        return json_dict

    @validator('level', pre=True)
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
    type: Literal['LOG'] = Field(const=True, default='LOG')
    message: str
    key_values: dict[str, str] = Field(default_factory=dict)


class NCCallBeginEntry(_BaseNCEntry):
    """An entry representing a single method call beginning in a NC execution."""
    type: Literal['CALL_BEGIN'] = Field(const=True, default='CALL_BEGIN')
    level: NCLogLevel = Field(const=True, default=NCLogLevel.DEBUG)
    nc_id: VertexId
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

    @override
    def dict(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        json_dict = super().dict(*args, **kwargs)
        json_dict['nc_id'] = self.nc_id.hex()
        return json_dict

    @validator('nc_id', pre=True)
    def _parse_nc_id(cls, vertex_id: VertexId | str) -> VertexId:
        if isinstance(vertex_id, VertexId):
            return vertex_id
        if isinstance(vertex_id, str):
            return bytes.fromhex(vertex_id)
        raise TypeError(f'invalid vertex_id type: {type(vertex_id)}')


class NCCallEndEntry(_BaseNCEntry):
    """An entry representing a single method call ending in a NC execution."""
    type: Literal['CALL_END'] = Field(const=True, default='CALL_END')
    level: NCLogLevel = Field(const=True, default=NCLogLevel.DEBUG)


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
        return self.copy(
            update=dict(
                logs=[log for log in self.logs if log.level >= log_level],
            ),
        )


class NCExecEntries(BaseModel):
    """
    A mapping of block IDs to lists of NC executions.
    If there are reorgs, a single block can execute the same NC more than once.
    """
    entries: dict[VertexId, list[NCExecEntry]]

    @staticmethod
    def from_json(json_dict: dict[str, Any]) -> NCExecEntries:
        entries = {
            bytes.fromhex(block_id_hex): [NCExecEntry.parse_obj(entry) for entry in entries]
            for block_id_hex, entries in json_dict.items()
        }
        return NCExecEntries(entries=entries)

    @override
    def dict(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            block_id.hex(): [entry.dict(*args, **kwargs) for entry in block_entries]
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
    __reactor__: ReactorProtocol
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


class NCLogStorage:
    """
    A storage to persist NC execution logs in the file system.
    """
    __slots__ = ('settings', '_path', '_config')

    def __init__(self, *, settings: HathorSettings, path: str, config: NCLogConfig) -> None:
        self.settings = settings
        self._path = Path(path).joinpath(NC_EXEC_LOGS_DIR)
        self._config = config

    def save_logs(self, tx: Transaction, call_info: CallInfo, exception_and_tb: tuple[NCFail, str] | None) -> None:
        """Persist new NC execution logs."""
        assert tx.is_nano_contract()
        meta = tx.get_metadata()
        assert meta.first_block is not None, 'nc exec logs can only be saved when the nc is confirmed'
        exception, tb = exception_and_tb if exception_and_tb is not None else (None, None)

        match self._config:
            case NCLogConfig.NONE:
                # don't save any logs
                return
            case NCLogConfig.ALL:
                # save all logs
                pass
            case NCLogConfig.FAILED:
                if exception is None:
                    # don't save when there's no exception
                    return
            case NCLogConfig.FAILED_UNHANDLED:
                if exception is None:
                    # don't save when there's no exception
                    return
                assert isinstance(exception, NCFail)
                if not exception.__cause__ or isinstance(exception.__cause__, NCFail):
                    # don't save when it's a simple NCFail or caused by a NCFail
                    return
            case _:
                assert_never(self._config)

        new_entry = NCExecEntry.from_call_info(call_info, tb)
        new_line_dict = {meta.first_block.hex(): new_entry.dict()}
        path = self._get_file_path(tx.hash)

        with path.open(mode='a') as f:
            f.write(json.dumps(new_line_dict) + '\n')

    def _get_file_path(self, vertex_id: VertexId) -> Path:
        dir_path = self._path.joinpath(vertex_id[0:1].hex())
        os.makedirs(dir_path, exist_ok=True)
        return dir_path.joinpath(f'{vertex_id.hex()}.jsonl')

    def _get_entries(self, nano_contract_id: VertexId, *, block_id: VertexId | None) -> NCExecEntries | None:
        """Internal method to get NCExecEntries from the file system, or None if it doesn't exist."""
        path = self._get_file_path(nano_contract_id)
        if not os.path.isfile(path):
            return None

        all_execs = defaultdict(list)
        with path.open(mode='r') as f:
            for line in f:
                if not line:
                    break
                line_dict = json.loads(line)
                keys = list(line_dict.keys())
                assert len(line_dict.keys()) == 1
                block_id_key = keys[0]
                if block_id is None or block_id_key == block_id.hex():
                    all_execs[block_id_key].append(line_dict[block_id_key])

        return NCExecEntries.from_json(all_execs)

    def get_logs(
        self,
        nano_contract_id: VertexId,
        *,
        log_level: NCLogLevel = NCLogLevel.DEBUG,
        block_id: VertexId | None = None,
    ) -> NCExecEntries | None:
        """
        Return NC execution logs to the provided NC ID.

        Args:
            nano_contract_id: the id of the NC to be retrieved.
            log_level: the minimum log level of desired logs.
            block_id: optional block ID of the block that executed the NC.

        Returns:
            A dict of block IDs to lists of NCExecEntry.
        """
        logs = self._get_entries(nano_contract_id, block_id=block_id)
        if logs is None:
            return None
        entries = {
            exec_block_id: [nc_exec_entry.filter(log_level) for nc_exec_entry in entries]
            for exec_block_id, entries in logs.entries.items()
        }
        return NCExecEntries(entries=entries)

    def get_json_logs(
        self,
        nano_contract_id: VertexId,
        *,
        log_level: NCLogLevel = NCLogLevel.DEBUG,
        block_id: VertexId | None = None,
    ) -> dict[str, Any] | None:
        """Return NC execution logs to the provided NC ID as json."""
        logs = self.get_logs(nano_contract_id, log_level=log_level, block_id=block_id)
        return None if logs is None else logs.dict()
