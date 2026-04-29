# Copyright 2026 Hathor Labs
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

from hathorlib.nanocontracts.nc_exec_logs import NCEvent, NCExecEntry
from hathorlib.nanocontracts.types import VertexId


class EventStore:
    """Stores events and logs from simulation execution, queryable by tx or block."""

    def __init__(self) -> None:
        self._events_by_tx: dict[VertexId, list[NCEvent]] = {}
        self._events_by_block: dict[VertexId, list[NCEvent]] = {}
        self._logs_by_tx: dict[VertexId, NCExecEntry] = {}
        self._logs_by_block: dict[VertexId, list[NCExecEntry]] = {}
        self._all_events: list[NCEvent] = []
        self._all_logs: list[NCExecEntry] = []

    def record_tx(
        self,
        *,
        tx_hash: VertexId,
        block_hash: VertexId,
        events: list[NCEvent],
        exec_entry: NCExecEntry | None,
    ) -> None:
        """Record events and logs for a transaction."""
        self._events_by_tx[tx_hash] = events
        self._all_events.extend(events)

        # Append to block-level collections
        if block_hash not in self._events_by_block:
            self._events_by_block[block_hash] = []
        self._events_by_block[block_hash].extend(events)

        if exec_entry is not None:
            self._logs_by_tx[tx_hash] = exec_entry
            self._all_logs.append(exec_entry)
            if block_hash not in self._logs_by_block:
                self._logs_by_block[block_hash] = []
            self._logs_by_block[block_hash].append(exec_entry)

    def get_events(
        self,
        *,
        tx_hash: VertexId | None = None,
        block_hash: VertexId | None = None,
    ) -> list[NCEvent]:
        """Get events filtered by tx_hash, block_hash, or all events."""
        if tx_hash is not None:
            return list(self._events_by_tx.get(tx_hash, []))
        if block_hash is not None:
            return list(self._events_by_block.get(block_hash, []))
        return list(self._all_events)

    def get_logs(
        self,
        *,
        tx_hash: VertexId | None = None,
        block_hash: VertexId | None = None,
    ) -> list[NCExecEntry]:
        """Get execution logs filtered by tx_hash, block_hash, or all logs."""
        if tx_hash is not None:
            entry = self._logs_by_tx.get(tx_hash)
            return [entry] if entry else []
        if block_hash is not None:
            return list(self._logs_by_block.get(block_hash, []))
        return list(self._all_logs)
