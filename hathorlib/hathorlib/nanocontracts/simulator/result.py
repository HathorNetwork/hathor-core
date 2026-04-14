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

from dataclasses import dataclass

from hathorlib.nanocontracts.nc_exec_logs import NCEvent, NCExecEntry
from hathorlib.nanocontracts.types import ContractId, VertexId


@dataclass(frozen=True, slots=True)
class TxResult:
    """Result of a single call_public or create_contract call."""
    tx_hash: VertexId
    block_hash: VertexId
    contract_id: ContractId
    events: list[NCEvent]
    exec_entry: NCExecEntry | None


@dataclass(frozen=True, slots=True)
class BlockResult:
    """Result of new_block(), summarizing all transactions in the block."""
    block_hash: VertexId
    block_height: int
    tx_results: list[TxResult]
