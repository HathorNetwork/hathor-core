# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from hathorlib.nanocontracts.nc_exec_logs import NCEvent, NCExecEntry
from hathorlib.nanocontracts.types import ContractId, VertexId


@dataclass(frozen=True, slots=True)
class NcCallResult:
    """Result of a single call_public or create_contract call."""
    tx_hash: VertexId
    block_hash: VertexId
    contract_id: ContractId
    events: list[NCEvent]
    exec_entry: NCExecEntry | None


@dataclass(frozen=True, slots=True)
class NcExecResult:
    """Result of new_block(), summarizing all transactions in the block."""
    block_hash: VertexId
    block_height: int
    tx_results: list[NcCallResult]
