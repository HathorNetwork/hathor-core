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

"""Dry-run execution of NC blocks without state modification."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, Optional

from pydantic import Field

from hathor.nanocontracts.execution.block_executor import (
    NCBeginBlock,
    NCBeginTransaction,
    NCEndBlock,
    NCTxExecutionFailure,
    NCTxExecutionSkipped,
    NCTxExecutionSuccess,
)
from hathor.api.schemas.base import ResponseModel
from hathor.utils.pydantic import BaseModel, Hex


class ExecutionStatus(StrEnum):
    SUCCESS = 'success'
    FAILURE = 'failure'
    SKIPPED = 'skipped'


if TYPE_CHECKING:
    from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
    from hathor.transaction import Block


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
    nc_sorted_calls: list[Hex[bytes]] = Field(description="TX hashes in execution order")
    transactions: list[DryRunTxResult] = Field(description="Results for each transaction")
    target_tx_hash: Optional[Hex[bytes]] = Field(default=None, description="Target TX hash when queried via tx_hash")
    warning: Optional[str] = Field(default=None, description="Warning message (e.g., non-determinism detected)")


class NCDryRunBlockExecutor:
    """
    Executor for dry-running NC block execution.

    This class provides a unified interface for dry-running blocks without
    modifying state. It wraps NCBlockExecutor and collects execution effects
    into a structured result.
    """

    def __init__(self, block_executor: 'NCBlockExecutor') -> None:
        """
        Initialize the dry-run executor.

        Args:
            block_executor: The pure block executor to use for execution.
        """
        self._block_executor = block_executor

    def execute(
        self,
        block: 'Block',
        *,
        include_changes: bool = False,
        target_tx_hash: Optional[bytes] = None,
    ) -> DryRunResult:
        """
        Execute a dry run of the given block.

        Args:
            block: The block to dry-run.
            include_changes: Whether to include storage state changes in call records.
            target_tx_hash: Optional TX hash when looking up via transaction.

        Returns:
            DryRunResult containing all execution information.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        from hathor.transaction import Transaction

        block_meta = block.get_metadata()
        nc_block_root_id = block_meta.nc_block_root_id
        expected_root_id = nc_block_root_id or b''

        # Track voided txs in-memory during execution; tx_deps is populated
        # from the NCBeginBlock effect to avoid a separate BFS traversal.
        voided_in_block: set[bytes] = set()
        tx_deps: dict[bytes, set[bytes]] = {}
        nc_tx_set: set[bytes] = set()

        def should_skip(tx: Transaction) -> bool:
            # Check if any dependency (within block's NC txs) was voided
            deps = tx_deps.get(tx.hash, set())
            if deps & voided_in_block:
                return True

            # Check pre-existing voided state (ignore NC_EXECUTION_FAIL_ID)
            meta = tx.get_metadata()
            if meta.voided_by:
                non_nc_voided = meta.voided_by - {NC_EXECUTION_FAIL_ID, tx.hash}
                if non_nc_voided:
                    return True

            return False

        # Initialize result containers
        initial_block_root_id = b''
        final_block_root_id = b''
        nc_sorted_calls: list[bytes] = []
        transactions: list[DryRunTxResult] = []
        current_rng_seed: Optional[bytes] = None

        for effect in self._block_executor.execute_block(block, should_skip=should_skip):
            match effect:
                case NCBeginBlock(parent_root_id=parent_root_id, nc_sorted_calls=calls):
                    initial_block_root_id = parent_root_id
                    nc_sorted_calls = [tx.hash for tx in calls]
                    # Build dependency graph from the already-collected NC txs
                    nc_tx_set = set(nc_sorted_calls)
                    for tx in calls:
                        tx_deps[tx.hash] = {txin.tx_id for txin in tx.inputs} & nc_tx_set

                case NCBeginTransaction(rng_seed=rng_seed):
                    current_rng_seed = rng_seed

                case NCTxExecutionSuccess(tx=tx, runner=runner):
                    tx_result = self._build_success_result(
                        tx, current_rng_seed, runner, include_changes
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCTxExecutionFailure(tx=tx, runner=runner, exception=exception, traceback=tb):
                    # Mark this tx as voided for subsequent transactions
                    voided_in_block.add(tx.hash)
                    tx_result = self._build_failure_result(
                        tx, current_rng_seed, runner, exception, tb, include_changes
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCTxExecutionSkipped(tx=tx):
                    # Also mark skipped txs as voided (propagate through chain)
                    voided_in_block.add(tx.hash)
                    tx_result = DryRunTxResult(
                        tx_hash=tx.hash,
                        rng_seed=current_rng_seed if current_rng_seed is not None else b'',
                        execution_status=ExecutionStatus.SKIPPED,
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCEndBlock(final_root_id=root_id):
                    final_block_root_id = root_id

        # Compare computed root with expected
        warning = None
        if nc_block_root_id is None:
            root_id_matches = True
            warning = 'Block has not been executed yet; cannot compare root IDs'
        else:
            root_id_matches = final_block_root_id == expected_root_id
            if not root_id_matches:
                warning = (
                    f'Non-deterministic execution detected: computed root {final_block_root_id.hex()} '
                    f'differs from expected root {expected_root_id.hex()}'
                )

        return DryRunResult(
            block_hash=block.hash,
            block_height=block.get_height(),
            initial_block_root_id=initial_block_root_id,
            final_block_root_id=final_block_root_id,
            expected_block_root_id=expected_root_id,
            root_id_matches=root_id_matches,
            nc_sorted_calls=nc_sorted_calls,
            transactions=transactions,
            target_tx_hash=target_tx_hash,
            warning=warning,
        )

    def _build_success_result(
        self,
        tx: Any,
        rng_seed: Optional[bytes],
        runner: Any,
        include_changes: bool,
    ) -> DryRunTxResult:
        """Build result for successful execution."""
        call_info = runner.get_last_call_info()
        call_records = self._build_call_records(call_info, include_changes)
        events = self._build_events(call_info)

        return DryRunTxResult(
            tx_hash=tx.hash,
            rng_seed=rng_seed if rng_seed is not None else b'',
            execution_status=ExecutionStatus.SUCCESS,
            call_records=call_records,
            events=events,
        )

    def _build_failure_result(
        self,
        tx: Any,
        rng_seed: Optional[bytes],
        runner: Any,
        exception: Exception,
        tb: str,
        include_changes: bool,
    ) -> DryRunTxResult:
        """Build result for failed execution."""
        call_info = runner.get_last_call_info()
        call_records = self._build_call_records(call_info, include_changes)

        return DryRunTxResult(
            tx_hash=tx.hash,
            rng_seed=rng_seed if rng_seed is not None else b'',
            execution_status=ExecutionStatus.FAILURE,
            call_records=call_records,
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            traceback=tb,
        )

    def _build_call_records(self, call_info: Any, include_changes: bool) -> list[DryRunCallRecord]:
        """Build call records from CallInfo."""
        records: list[DryRunCallRecord] = []
        if call_info.calls is None:
            return records

        for call in call_info.calls:
            index_updates: list[dict[str, Any]] = []
            if call.index_updates is not None:
                for update in call.index_updates:
                    index_updates.append(update.to_json())

            changes = None
            if include_changes:
                changes = self._extract_changes(call.changes_tracker)

            record = DryRunCallRecord(
                type=call.type.value,
                depth=call.depth,
                contract_id=call.contract_id,
                blueprint_id=call.blueprint_id,
                method_name=call.method_name,
                index_updates=index_updates,
                changes=changes,
            )
            records.append(record)

        return records

    def _extract_changes(self, changes_tracker: Any) -> list[dict[str, Any]]:
        """Extract storage changes from a changes tracker."""
        changes: list[dict[str, Any]] = []
        for attr_key, (value, _nc_type) in changes_tracker.data.items():
            change = {
                'key': attr_key.key.hex(),
                'value': repr(value),
            }
            changes.append(change)
        return changes

    def _build_events(self, call_info: Any) -> list[dict[str, Any]]:
        """Build events from CallInfo."""
        events: list[dict[str, Any]] = []
        for event in call_info.nc_logger.__events__:
            events.append({
                'nc_id': event.nc_id.hex(),
                'data': event.data.hex(),
            })
        return events
