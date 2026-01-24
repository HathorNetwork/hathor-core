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

"""NCConsensusBlockExecutor - Applies side effects from nano contract execution."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable, Protocol

from structlog import get_logger
from typing_extensions import assert_never

from hathor.execution_manager import non_critical_code
from hathor.nanocontracts.execution.block_executor import (
    NCBeginBlock,
    NCBeginTransaction,
    NCEndBlock,
    NCEndTransaction,
    NCTxExecutionFailure,
    NCTxExecutionSkipped,
    NCTxExecutionSuccess,
    ShouldSkipPredicate,
)
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.types import MetaNCCallRecord

if TYPE_CHECKING:
    from collections.abc import Iterator

    from hathor.conf.settings import HathorSettings
    from hathor.consensus.context import ConsensusAlgorithmContext
    from hathor.nanocontracts.execution.block_executor import NCBlockEffect
    from hathor.nanocontracts.execution.subprocess_block_executor import NCBlockEffectExtended
    from hathor.nanocontracts.nc_exec_logs import NCLogStorage
    from hathor.nanocontracts.storage import NCStorageFactory


class BlockExecutorProtocol(Protocol):
    """Protocol for block executors (NCBlockExecutor or NCSubprocessBlockExecutor)."""

    def execute_block(
        self,
        block: Block,
        *,
        should_skip: ShouldSkipPredicate,
        nc_txs: list[Transaction],
        parent_root_id: bytes,
    ) -> 'Iterator[NCBlockEffect | NCBlockEffectExtended]':
        ...


logger = get_logger()

_base_transaction_log = logger.new()


class NCConsensusBlockExecutor:
    """
    Applies side effects from nano contract block execution.

    This class handles all state mutations, logging, and persistence
    during block execution. It uses NCBlockExecutor (or NCSubprocessBlockExecutor)
    for pure execution and applies the resulting effects.

    When using NCSubprocessBlockExecutor, transaction execution results contain
    serialized runner data instead of full Runner objects. The executor handles
    both variants transparently.
    """

    def __init__(
        self,
        *,
        settings: 'HathorSettings',
        block_executor: 'BlockExecutorProtocol',
        nc_storage_factory: 'NCStorageFactory',
        nc_log_storage: 'NCLogStorage',
        nc_exec_fail_trace: bool = False,
    ) -> None:
        """
        Initialize the consensus block executor.

        Args:
            settings: Hathor settings.
            block_executor: The block executor for NC execution
                (NCBlockExecutor or NCSubprocessBlockExecutor).
            nc_storage_factory: Factory to create NC storage instances.
            nc_log_storage: Storage for NC execution logs.
            nc_exec_fail_trace: Whether to include stack traces in failure logs.
        """
        self._settings = settings
        self._block_executor = block_executor
        self._nc_storage_factory = nc_storage_factory
        self._nc_log_storage = nc_log_storage
        self._nc_exec_fail_trace = nc_exec_fail_trace

    @property
    def log(self) -> Any:
        return _base_transaction_log

    def initialize_empty(self, block: Block, context: 'ConsensusAlgorithmContext') -> None:
        """Initialize a block with an empty contract trie."""
        meta = block.get_metadata()
        block_storage = self._nc_storage_factory.get_empty_block_storage()
        block_storage.commit()
        if meta.nc_block_root_id is not None:
            assert meta.nc_block_root_id == block_storage.get_root_id()
        else:
            meta.nc_block_root_id = block_storage.get_root_id()
            context.save(block)

    def execute_chain(
        self,
        block: Block,
        context: 'ConsensusAlgorithmContext',
        *,
        on_failure: Callable[[Transaction], None],
    ) -> None:
        """Execute NC transactions for a block and any pending parent blocks, handling reorgs.

        This method determines which blocks need execution (handling reorgs) and
        executes them in order from oldest to newest."""
        # If we reach this point, Nano Contracts must be enabled.
        assert self._settings.ENABLE_NANO_CONTRACTS
        assert not block.is_genesis

        meta = block.get_metadata()
        if meta.voided_by:
            # If the block is voided, skip execution.
            return

        assert meta.nc_block_root_id is None

        to_be_executed: list[Block] = []
        is_reorg: bool = False
        if context.reorg_info:
            # handle reorgs
            is_reorg = True
            cur = block
            # XXX We could stop when `cur_meta.nc_block_root_id is not None` but
            #     first we need to refactor meta.first_block and meta.voided_by to
            #     have different values per block.
            while cur != context.reorg_info.common_block:
                cur_meta = cur.get_metadata()
                if cur_meta.nc_block_root_id is not None:
                    # Reset nc_block_root_id to force re-execution.
                    cur_meta.nc_block_root_id = None
                to_be_executed.append(cur)
                cur = cur.get_block_parent()
        else:
            # No reorg occurred, so we execute all unexecuted blocks.
            # Normally it's just the current block, but it's possible to have
            # voided and therefore unexecuted blocks connected to the best chain,
            # for example when a block is voided by a transaction.
            cur = block
            while True:
                cur_meta = cur.get_metadata()
                if cur_meta.nc_block_root_id is not None:
                    break
                to_be_executed.append(cur)
                if cur.is_genesis:
                    break
                cur = cur.get_block_parent()

        for current in to_be_executed[::-1]:
            self.execute_block_and_apply(current, context, is_reorg=is_reorg, on_failure=on_failure)

    def execute_block_and_apply(
        self,
        block: Block,
        context: 'ConsensusAlgorithmContext',
        *,
        is_reorg: bool,
        on_failure: Callable[[Transaction], None],
    ) -> None:
        """Execute block and apply all effects (current behavior).

        This wraps execute_block() and applies each effect, maintaining backward
        compatibility with the original behavior.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID

        assert self._settings.ENABLE_NANO_CONTRACTS

        if block.is_genesis:
            # XXX We can remove this call after the full node initialization is refactored and
            #     the genesis block goes through the consensus protocol.
            self.initialize_empty(block, context)
            return

        # Verify block hasn't been executed yet
        meta = block.get_metadata()
        assert meta.nc_block_root_id is None

        # Get parent_root_id from parent block's metadata
        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()
        parent_root_id = parent_meta.nc_block_root_id
        assert parent_root_id is not None

        # Get NC transactions from block
        nc_txs: list[Transaction] = [
            tx for tx in block.iter_transactions_in_this_block()
            if tx.is_nano_contract()
        ]

        # Create predicate that reads from database metadata
        def should_skip(tx: Transaction) -> bool:
            tx_meta = tx.get_metadata()
            return bool(tx_meta.voided_by)

        # Track NC transactions for final verification (populated from NCBeginBlock)
        nc_sorted_calls: list[Transaction] = []

        for effect in self._block_executor.execute_block(
            block,
            should_skip=should_skip,
            nc_txs=nc_txs,
            parent_root_id=parent_root_id,
        ):
            match effect:
                case NCBeginBlock(nc_sorted_calls=nc_sorted_calls):
                    pass
                case _:
                    pass
            self._apply_effect(effect, context, on_failure)

        # Log and verify execution states for all transactions
        for tx in nc_sorted_calls:
            tx_meta = tx.get_metadata()
            assert tx_meta.nc_execution is not None
            self.log.info('nano tx execution status',
                          blk=block.hash.hex(),
                          tx=tx.hash.hex(),
                          execution=tx_meta.nc_execution.value)
            match tx_meta.nc_execution:
                case NCExecutionState.PENDING:  # pragma: no cover
                    assert False, 'unexpected pending state'  # should never happen
                case NCExecutionState.SUCCESS:
                    assert tx_meta.voided_by is None
                case NCExecutionState.FAILURE:
                    assert tx_meta.voided_by == {tx.hash, NC_EXECUTION_FAIL_ID}
                case NCExecutionState.SKIPPED:
                    assert tx_meta.voided_by
                    assert NC_EXECUTION_FAIL_ID not in tx_meta.voided_by
                case _:  # pragma: no cover
                    assert_never(tx_meta.nc_execution)

    def _apply_effect(
        self,
        effect: 'NCBlockEffect | NCBlockEffectExtended',
        context: 'ConsensusAlgorithmContext',
        on_failure: Callable[[Transaction], None],
    ) -> None:
        """Apply a single effect from the generator.

        Handles both regular effects (from NCBlockExecutor) and serialized
        effects (from NCSubprocessBlockExecutor).

        Args:
            effect: The effect to apply.
            context: Consensus algorithm context for saving state.
            on_failure: Callback for failed transactions.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        from hathor.nanocontracts.execution.subprocess_block_executor import (
            NCTxExecutionFailureSerialized,
            NCTxExecutionSuccessSerialized,
        )

        match effect:
            case NCBeginBlock():
                # Nothing to apply at block start
                pass

            case NCBeginTransaction(tx=tx):
                # Verify transaction hasn't been executed yet
                tx_meta = tx.get_metadata()
                assert tx_meta.nc_execution in {None, NCExecutionState.PENDING}
                if tx_meta.voided_by:
                    # During normal execution, NC_EXECUTION_FAIL_ID should not be in voided_by
                    # as that is added by the executor itself after a failure
                    assert NC_EXECUTION_FAIL_ID not in tx_meta.voided_by

            case NCTxExecutionSuccess(tx=tx, runner=runner):
                from hathor.nanocontracts.runner.call_info import CallType

                tx_meta = tx.get_metadata()

                tx_meta.nc_execution = NCExecutionState.SUCCESS
                context.save(tx)

                # Commit the runner changes
                # TODO Avoid calling multiple commits for the same contract. The best would be
                #      to call the commit method once per contract per block, just like we do
                #      for the block_storage. This ensures we will have a clean database with
                #      no orphan nodes.
                runner.commit()

                # Derive call_info, nc_calls_records, and events from runner
                call_info = runner.get_last_call_info()
                assert call_info.calls is not None
                nc_calls_records = [
                    MetaNCCallRecord.from_call_record(call)
                    for call in call_info.calls if call.type == CallType.PUBLIC
                ]
                events_list = call_info.nc_logger.__events__

                # Update metadata with call records
                assert tx_meta.nc_calls is None
                tx_meta.nc_calls = nc_calls_records
                context.save(tx)

                # Update indexes. This must be after metadata is updated.
                assert tx.storage is not None
                with non_critical_code(self.log):
                    tx.storage.indexes.non_critical_handle_contract_execution(tx)

                # Pubsub event to indicate execution success
                context.nc_exec_success.append(tx)

                # Store events for pubsub
                assert context.nc_events is not None
                context.nc_events.append((tx, events_list))

                # Store events in transaction metadata
                if events_list:
                    tx_meta.nc_events = [(event.nc_id, event.data) for event in events_list]
                    context.save(tx)

                # Save logs
                self._nc_log_storage.save_logs(tx, call_info, None)

            case NCTxExecutionSuccessSerialized(tx=tx, serialized_runner=serialized_runner):
                # Handle serialized success from subprocess execution
                # Note: Storage was already committed by subprocess, so NO commit call here
                tx_meta = tx.get_metadata()

                tx_meta.nc_execution = NCExecutionState.SUCCESS
                context.save(tx)

                # Reconstruct call records and events from serialized data
                nc_calls_records, events_list = self._reconstruct_from_serialized(
                    serialized_runner.call_info_json
                )

                # Update metadata with call records
                assert tx_meta.nc_calls is None
                tx_meta.nc_calls = nc_calls_records
                context.save(tx)

                # Update indexes. This must be after metadata is updated.
                assert tx.storage is not None
                with non_critical_code(self.log):
                    tx.storage.indexes.non_critical_handle_contract_execution(tx)

                # Pubsub event to indicate execution success
                context.nc_exec_success.append(tx)

                # Store events for pubsub
                assert context.nc_events is not None
                context.nc_events.append((tx, events_list))

                # Store events in transaction metadata
                if events_list:
                    tx_meta.nc_events = [(event.nc_id, event.data) for event in events_list]
                    context.save(tx)

                # Save logs (minimal for subprocess execution)
                self._nc_log_storage.save_logs_from_json(tx, serialized_runner.call_info_json, None)

            case NCTxExecutionFailure(tx=tx, runner=runner, exception=exception, traceback=tb):
                # Log the failure
                kwargs: dict[str, Any] = {}
                if tx.name:
                    kwargs['__name'] = tx.name
                if self._nc_exec_fail_trace:
                    kwargs['exc_info'] = True
                self.log.info(
                    'nc execution failed',
                    tx=tx.hash.hex(),
                    error=repr(exception),
                    cause=repr(exception.__cause__),
                    **kwargs,
                )

                on_failure(tx)

                # Save logs with exception info
                call_info = runner.get_last_call_info()
                self._nc_log_storage.save_logs(tx, call_info, (exception, tb))

            case NCTxExecutionFailureSerialized(
                tx=tx,
                serialized_runner=serialized_runner,
                exception_repr=exception_repr,
                exception_cause_repr=exception_cause_repr,
                traceback=tb,
            ):
                # Handle serialized failure from subprocess execution
                log_kwargs: dict[str, Any] = {}
                if tx.name:
                    log_kwargs['__name'] = tx.name
                self.log.info(
                    'nc execution failed (subprocess)',
                    tx=tx.hash.hex(),
                    error=exception_repr,
                    cause=exception_cause_repr,
                    **log_kwargs,
                )

                on_failure(tx)

                # Save logs with exception info (from JSON)
                self._nc_log_storage.save_logs_from_json(
                    tx,
                    serialized_runner.call_info_json,
                    (exception_repr, tb),
                )

            case NCTxExecutionSkipped(tx=tx):
                tx_meta = tx.get_metadata()
                tx_meta.nc_execution = NCExecutionState.SKIPPED
                context.save(tx)

            case NCEndTransaction():
                # Nothing to apply at transaction end
                pass

            case NCEndBlock(block=block, block_storage=block_storage, final_root_id=final_root_id):
                # Commit block storage and save block metadata
                # Note: For subprocess execution, storage was already committed,
                # but commit() is idempotent for content-addressed storage
                block_storage.commit()
                root_id = block_storage.get_root_id()
                assert root_id is not None
                # Verify root matches if provided (subprocess case)
                if final_root_id != root_id:
                    # In subprocess case, use the final_root_id that was computed
                    root_id = final_root_id
                meta = block.get_metadata()
                meta.nc_block_root_id = root_id
                context.save(block)

            case _:
                assert_never(effect)

    def _reconstruct_from_serialized(
        self,
        call_info_json: str,
    ) -> tuple[list[MetaNCCallRecord], list[Any]]:
        """Reconstruct call records and events from serialized call_info JSON.

        Args:
            call_info_json: JSON string from SerializedRunner

        Returns:
            Tuple of (nc_calls_records, events_list)
        """
        from hathor.nanocontracts.nc_exec_logs import NCEvent
        from hathor.nanocontracts.runner.index_records import nc_index_update_record_from_json
        from hathor.nanocontracts.types import ContractId, VertexId

        data = json.loads(call_info_json)

        # Reconstruct nc_calls_records from JSON
        nc_calls_records: list[MetaNCCallRecord] = []
        for call_data in data.get('calls', []):
            if call_data.get('type') != 'public':
                continue

            # Reconstruct index_updates from JSON
            index_updates = []
            for update_data in call_data.get('index_updates', []):
                index_update = nc_index_update_record_from_json(update_data)
                index_updates.append(index_update)

            record = MetaNCCallRecord(
                contract_id=bytes.fromhex(call_data['contract_id']),
                blueprint_id=bytes.fromhex(call_data['blueprint_id']),
                method_name=call_data['method_name'],
                index_updates=index_updates,
            )
            nc_calls_records.append(record)

        # Reconstruct events from JSON
        events_list: list[NCEvent] = []
        for event_data in data.get('events', []):
            event = NCEvent(
                nc_id=ContractId(VertexId(bytes.fromhex(event_data['nc_id']))),
                data=bytes.fromhex(event_data['data']),
            )
            events_list.append(event)

        return nc_calls_records, events_list
