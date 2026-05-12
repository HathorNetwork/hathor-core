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

"""Dry-run execution of NC blocks without state modification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from typing_extensions import assert_never

from hathor.nanocontracts.execution.block_executor import (
    NCBeginBlock,
    NCBeginTransaction,
    NCEndBlock,
    NCEndTransaction,
    NCTxExecutionFailure,
    NCTxExecutionSkipped,
    NCTxExecutionSuccess,
)
from hathor.nanocontracts.execution.dry_run_models import (
    DryRunCallRecord,
    DryRunResult,
    DryRunTxResult,
    ExecutionStatus,
)

if TYPE_CHECKING:
    from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
    from hathor.transaction import Block


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

        def should_skip(tx: Transaction) -> bool:
            # Check if any dependency (within block's NC txs) was voided
            deps = tx_deps.get(tx.hash, set())
            if deps & voided_in_block:
                return True

            # Mirror consensus's has_only_nc_execution_fail_id semantics: only
            # txs voided purely by their own NC execution failure are
            # re-executed; any other void reason (self-conflict, soft void,
            # voided by another tx) means consensus skipped it and dry-run
            # must too. Consensus invariant (consensus.py:283): NC_EXECUTION_FAIL_ID
            # in voided_by implies tx.hash is also in voided_by.
            meta = tx.get_metadata()
            if meta.voided_by and meta.voided_by != {NC_EXECUTION_FAIL_ID, tx.hash}:
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
                    if runner is None:
                        current_rng_seed = None
                        continue
                    tx_result = self._build_success_result(
                        tx, current_rng_seed, runner, include_changes
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCTxExecutionFailure(tx=tx, runner=runner, exception=exception, traceback=tb):
                    # Mark this tx as voided for subsequent transactions
                    voided_in_block.add(tx.hash)
                    if not tx.is_nano_contract():
                        current_rng_seed = None
                        continue
                    call_info = runner.get_last_call_info() if runner is not None else None
                    tx_result = self._build_failure_result(
                        tx, current_rng_seed, call_info, exception, tb, include_changes
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCTxExecutionSkipped(tx=tx):
                    # Also mark skipped txs as voided (propagate through chain)
                    voided_in_block.add(tx.hash)
                    if not tx.is_nano_contract():
                        current_rng_seed = None
                        continue
                    tx_result = DryRunTxResult(
                        tx_hash=tx.hash,
                        rng_seed=current_rng_seed if current_rng_seed is not None else b'',
                        execution_status=ExecutionStatus.SKIPPED,
                    )
                    transactions.append(tx_result)
                    current_rng_seed = None

                case NCEndTransaction():
                    pass

                case NCEndBlock(final_root_id=root_id):
                    final_block_root_id = root_id

                case _:
                    assert_never(effect)

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
        call_info: Any,
        exception: Exception,
        tb: str,
        include_changes: bool,
    ) -> DryRunTxResult:
        """Build result for failed execution.

        `call_info` is None for cyclic-dependency failures, which never run a Runner.
        """
        call_records = self._build_call_records(call_info, include_changes) if call_info is not None else []
        events = self._build_events(call_info) if call_info is not None else []

        return DryRunTxResult(
            tx_hash=tx.hash,
            rng_seed=rng_seed if rng_seed is not None else b'',
            execution_status=ExecutionStatus.FAILURE,
            call_records=call_records,
            events=events,
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
        """Extract storage changes from a changes tracker.

        Uses NCType.value_to_json for JSON-serializable output when the NCType is
        known; falls back to repr() only when nc_type is None (e.g., deletions) or
        value_to_json raises.
        """
        from hathorlib.nanocontracts.storage.changes_tracker import DeletedKey

        changes: list[dict[str, Any]] = []
        for attr_key, (value, nc_type) in changes_tracker.data.items():
            change: dict[str, Any] = {'key': attr_key.key.hex()}
            if value is DeletedKey:
                change['deleted'] = True
            elif nc_type is not None:
                try:
                    change['value'] = nc_type.value_to_json(value)
                except Exception:
                    change['value'] = repr(value)
            else:
                change['value'] = repr(value)
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
