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

from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field

from hathor.nanocontracts.execution.block_executor import (
    NCBeginBlock,
    NCBeginTransaction,
    NCEndBlock,
    NCTxExecutionFailure,
    NCTxExecutionSkipped,
    NCTxExecutionSuccess,
)
from hathor.nanocontracts.runner.call_info import CallType
from hathor.utils.api import Response

if TYPE_CHECKING:
    from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
    from hathor.transaction import Block


class DryRunCallRecord(Response):
    """A single call record from NC execution."""
    type: str = Field(description="Call type: 'public' or 'view'")
    depth: int = Field(description="Call depth in the execution stack")
    contract_id: str = Field(description="Hex-encoded contract ID")
    blueprint_id: str = Field(description="Hex-encoded blueprint ID")
    method_name: str = Field(description="Name of the called method")
    index_updates: list[dict[str, Any]] = Field(description="List of index updates from this call")
    changes: Optional[list[dict[str, Any]]] = Field(
        default=None, description="Storage state changes (when include_changes=True)"
    )


class DryRunTxResult(Response):
    """Result of dry-running a single transaction."""
    tx_hash: str = Field(description="Hex-encoded transaction hash")
    rng_seed: str = Field(description="Hex-encoded RNG seed used for this transaction")
    execution_status: str = Field(description="Execution status: 'success', 'failure', or 'skipped'")
    call_records: list[DryRunCallRecord] = Field(default=[], description="List of call records from execution")
    events: list[dict[str, Any]] = Field(default=[], description="Events emitted during execution")
    exception_type: Optional[str] = Field(default=None, description="Exception type name on failure")
    exception_message: Optional[str] = Field(default=None, description="Exception message on failure")
    traceback: Optional[str] = Field(default=None, description="Traceback string on failure")


class DryRunResult(Response):
    """Complete result from dry-running a block."""
    success: bool = Field(description="Whether the dry-run completed successfully")
    block_hash: str = Field(description="Hex-encoded block hash")
    block_height: int = Field(description="Block height")
    initial_block_root_id: str = Field(description="Hex-encoded NC root ID before execution")
    final_block_root_id: str = Field(description="Hex-encoded NC root ID after execution")
    expected_block_root_id: str = Field(description="Expected NC root ID from block metadata")
    root_id_matches: bool = Field(description="Whether computed root matches expected root")
    nc_sorted_calls: list[str] = Field(description="TX hashes in execution order")
    transactions: list[DryRunTxResult] = Field(description="Results for each transaction")
    target_tx_hash: Optional[str] = Field(default=None, description="Target TX hash when queried via tx_hash")
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
        target_tx_hash: Optional[str] = None,
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
        expected_root_id = block_meta.nc_block_root_id.hex() if block_meta.nc_block_root_id else ''

        # Build dependency graph for in-memory voided tracking
        tx_deps: dict[bytes, set[bytes]] = {}
        for tx in block.iter_transactions_in_this_block():
            if tx.is_nano_contract():
                tx_deps[tx.hash] = {txin.tx_id for txin in tx.inputs}

        # Track voided txs in-memory during execution
        voided_in_block: set[bytes] = set()

        def should_skip(tx: Transaction) -> bool:
            # Check if any dependency was voided during this execution
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
        initial_block_root_id = ''
        final_block_root_id = ''
        nc_sorted_calls: list[str] = []
        transactions: list[DryRunTxResult] = []
        current_rng_seed: Optional[str] = None

        for effect in self._block_executor.execute_block(block, should_skip=should_skip):
            match effect:
                case NCBeginBlock(parent_root_id=parent_root_id, nc_sorted_calls=calls):
                    initial_block_root_id = parent_root_id.hex()
                    nc_sorted_calls = [tx.hash.hex() for tx in calls]

                case NCBeginTransaction(rng_seed=rng_seed):
                    current_rng_seed = rng_seed.hex()

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
                        tx_hash=tx.hash.hex(),
                        rng_seed=current_rng_seed or '',
                        execution_status='skipped',
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCEndBlock(final_root_id=root_id):
                    final_block_root_id = root_id.hex()

        # Compare computed root with expected
        root_id_matches = final_block_root_id == expected_root_id
        warning = None
        if not root_id_matches:
            warning = (
                f'Non-deterministic execution detected: computed root {final_block_root_id} '
                f'differs from expected root {expected_root_id}'
            )

        return DryRunResult(
            success=True,
            block_hash=block.hash.hex(),
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
        rng_seed: Optional[str],
        runner: Any,
        include_changes: bool,
    ) -> DryRunTxResult:
        """Build result for successful execution."""
        call_info = runner.get_last_call_info()
        call_records = self._build_call_records(call_info, include_changes)
        events = self._build_events(call_info)

        return DryRunTxResult(
            tx_hash=tx.hash.hex(),
            rng_seed=rng_seed or '',
            execution_status='success',
            call_records=call_records,
            events=events,
        )

    def _build_failure_result(
        self,
        tx: Any,
        rng_seed: Optional[str],
        runner: Any,
        exception: Exception,
        tb: str,
        include_changes: bool,
    ) -> DryRunTxResult:
        """Build result for failed execution."""
        call_info = runner.get_last_call_info()
        call_records = self._build_call_records(call_info, include_changes)

        return DryRunTxResult(
            tx_hash=tx.hash.hex(),
            rng_seed=rng_seed or '',
            execution_status='failure',
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
                type=call.type.value if isinstance(call.type, CallType) else str(call.type),
                depth=call.depth,
                contract_id=call.contract_id.hex(),
                blueprint_id=call.blueprint_id.hex(),
                method_name=call.method_name,
                index_updates=index_updates,
                changes=changes,
            )
            records.append(record)

        return records

    def _extract_changes(self, changes_tracker: Any) -> list[dict[str, Any]]:
        """Extract storage changes from a changes tracker."""
        changes: list[dict[str, Any]] = []
        for attr_key, (value, nc_type) in changes_tracker.data.items():
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


def format_dry_run_text(result: DryRunResult, verbose: bool = False) -> str:
    """
    Format a DryRunResult as human-readable text.

    Args:
        result: The dry run result to format.
        verbose: Whether to include verbose output (tracebacks, changes).

    Returns:
        Formatted text string.
    """
    lines: list[str] = []

    # Header
    lines.append(f"Block: {result.block_hash} (height: {result.block_height})")
    lines.append(f"Initial Root:  {result.initial_block_root_id}")
    lines.append(f"Final Root:    {result.final_block_root_id}")
    lines.append(f"Expected Root: {result.expected_block_root_id}")

    if result.root_id_matches:
        lines.append('Root Match:    OK')
    else:
        lines.append('Root Match:    MISMATCH (non-deterministic execution detected!)')
        if result.warning:
            lines.append(f"WARNING: {result.warning}")
    lines.append('')

    # Execution order
    lines.append(f'Execution Order: {len(result.nc_sorted_calls)} transactions')
    for i, tx_hash in enumerate(result.nc_sorted_calls, 1):
        lines.append(f'  {i}. {tx_hash}')
    lines.append('')

    # Transaction details
    for i, tx in enumerate(result.transactions, 1):
        lines.append(f"--- Transaction {i}/{len(result.transactions)}: {tx.tx_hash} ---")
        lines.append(f"RNG Seed: {tx.rng_seed}")
        lines.append(f"Status: {tx.execution_status.upper()}")

        if tx.execution_status == 'failure':
            lines.append(f"Exception: {tx.exception_type or 'Unknown'} - {tx.exception_message or ''}")
            if verbose and tx.traceback:
                lines.append('Traceback:')
                for tb_line in tx.traceback.split('\n'):
                    lines.append(f'  {tb_line}')

        for j, call in enumerate(tx.call_records, 1):
            lines.append('')
            lines.append(f"  Call #{j}: {call.method_name} ({call.type}, depth={call.depth})")
            lines.append(f"    Contract: {call.contract_id}")
            lines.append(f"    Blueprint: {call.blueprint_id}")

            if call.index_updates:
                lines.append('    Index Updates:')
                for update in call.index_updates:
                    update_type = update.get('type', 'UNKNOWN')
                    if update_type == 'update_token_balance':
                        token = update.get('token_uid', 'N/A')
                        amount = update.get('amount', 'N/A')
                        lines.append(f"      - {update_type}: token={token}, amount={amount}")
                    else:
                        lines.append(f"      - {update}")

            if call.changes and verbose:
                lines.append('    Changes:')
                for change in call.changes:
                    lines.append(f"      - {change['key']}: {change['value']}")

        if tx.events:
            lines.append('  Events:')
            for event in tx.events:
                lines.append(f"    - nc_id={event['nc_id']}, data={event['data']}")

        lines.append('')

    return '\n'.join(lines)
