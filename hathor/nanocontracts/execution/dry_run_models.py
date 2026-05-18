#  Copyright 2026 Hathor Labs
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

"""Pydantic models for dry-run NC block execution results."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Optional

from pydantic import Field

from hathor.api.schemas.base import ResponseModel
from hathor.utils.pydantic import BaseModel, Hex


class ExecutionStatus(StrEnum):
    SUCCESS = 'success'
    FAILURE = 'failure'
    SKIPPED = 'skipped'


class DryRunCallRecord(BaseModel):
    """A single call record from NC execution."""
    type: str = Field(description="Call type: 'public' or 'view'")
    depth: int = Field(description="Call depth in the execution stack")
    contract_id: Hex[bytes] = Field(description="Contract ID")
    blueprint_id: Hex[bytes] = Field(description="Blueprint ID")
    method_name: str = Field(description="Name of the called method")
    index_updates: list[dict[str, Any]] = Field(description="List of index updates from this call")
    changes: Optional[list[dict[str, Any]]] = Field(
        default=None, description="Storage state changes (when include_changes=True)"
    )


class DryRunTxResult(BaseModel):
    """Result of dry-running a single transaction."""
    tx_hash: Hex[bytes] = Field(description="Transaction hash")
    rng_seed: Hex[bytes] = Field(description="RNG seed used for this transaction")
    execution_status: ExecutionStatus = Field(description="Execution status: 'success', 'failure', or 'skipped'")
    call_records: list[DryRunCallRecord] = Field(default=[], description="List of call records from execution")
    events: list[dict[str, Any]] = Field(default=[], description="Events emitted during execution")
    exception_type: Optional[str] = Field(default=None, description="Exception type name on failure")
    exception_message: Optional[str] = Field(default=None, description="Exception message on failure")
    traceback: Optional[str] = Field(default=None, description="Traceback string on failure")


class DryRunResult(ResponseModel):
    """Complete result from dry-running a block."""
    success: Literal[True] = Field(default=True, description="Whether the dry-run completed successfully")
    block_hash: Hex[bytes] = Field(description="Block hash")
    block_height: int = Field(description="Block height")
    initial_block_root_id: Hex[bytes] = Field(description="NC root ID before execution")
    final_block_root_id: Hex[bytes] = Field(description="NC root ID after execution")
    expected_block_root_id: Hex[bytes] = Field(description="Expected NC root ID from block metadata")
    root_id_matches: bool = Field(description="Whether computed root matches expected root")
    nc_sorted_calls: list[Hex[bytes]] = Field(
        description="TX hashes in execution order (same order as 'transactions' list)"
    )
    transactions: list[DryRunTxResult] = Field(
        description="Execution results for each NC transaction, in the same order as 'nc_sorted_calls'"
    )
    target_tx_hash: Optional[Hex[bytes]] = Field(default=None, description="Target TX hash when queried via tx_hash")
    warning: Optional[str] = Field(default=None, description="Warning message (e.g., non-determinism detected)")
