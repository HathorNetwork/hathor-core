# Copyright 2023 Hathor Labs
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

import hashlib
import traceback
from typing import TYPE_CHECKING, Any

from structlog import get_logger
from typing_extensions import assert_never

from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import TokenNotFound
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.types import MetaNCCallRecord

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.consensus.context import ConsensusAlgorithmContext
    from hathor.nanocontracts.nc_exec_logs import NCLogStorage
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.storage import NCBlockStorage

logger = get_logger()


class NCBlockRunner:
    def __init__(
        self,
        settings: HathorSettings,
        context: 'ConsensusAlgorithmContext',
        runner_factory: RunnerFactory,
        nc_log_storage: NCLogStorage,
        *,
        nc_exec_fail_trace: bool = False,
    ) -> None:
        self._settings = settings
        self.context = context
        self._runner_factory = runner_factory
        self._nc_log_storage = nc_log_storage
        self.nc_exec_fail_trace = nc_exec_fail_trace
        self.log = logger.new()

    def nc_initialize_empty(self, block: Block) -> None:
        """Initialize a block with an empty contract trie."""
        meta = block.get_metadata()
        block_storage = self.context.consensus.nc_storage_factory.get_empty_block_storage()
        block_storage.commit()
        if meta.nc_block_root_id is not None:
            assert meta.nc_block_root_id == block_storage.get_root_id()
        else:
            meta.nc_block_root_id = block_storage.get_root_id()
            self.context.save(block)

    def execute_nano_contracts(self, block: Block) -> None:
        """Execute the method calls for transactions confirmed by this block handling reorgs."""
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
        if self.context.reorg_info:
            # handle reorgs
            is_reorg = True
            cur = block
            # XXX We could stop when `cur_meta.nc_block_root_id is not None` but
            #     first we need to refactor meta.first_block and meta.voided_by to
            #     have different values per block.
            while cur != self.context.reorg_info.common_block:
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
            self._nc_execute_calls(current, is_reorg=is_reorg)

    def _nc_execute_calls(self, block: Block, *, is_reorg: bool) -> None:
        """Internal method to execute the method calls for transactions confirmed by this block.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID, NCFail
        from hathor.nanocontracts.types import Address

        assert self._settings.ENABLE_NANO_CONTRACTS

        if block.is_genesis:
            # XXX We can remove this call after the full node initialization is refactored and
            #     the genesis block goes through the consensus protocol.
            self.nc_initialize_empty(block)
            return

        meta = block.get_metadata()
        assert not meta.voided_by
        assert meta.nc_block_root_id is None

        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()
        block_root_id = parent_meta.nc_block_root_id
        assert block_root_id is not None

        nc_calls: list[Transaction] = []
        for tx in block.iter_transactions_in_this_block():
            if not tx.is_nano_contract():
                # Skip other type of transactions.
                continue
            tx_meta = tx.get_metadata()
            if is_reorg:
                assert self.context.reorg_info is not None
                # Clear the NC_EXECUTION_FAIL_ID flag if this is the only reason the transaction was voided.
                # This case might only happen when handling reorgs.
                assert tx.storage is not None
                if tx_meta.voided_by == {tx.hash, NC_EXECUTION_FAIL_ID}:
                    if tx_meta.conflict_with:
                        for tx_conflict_id in tx_meta.conflict_with:
                            tx_conflict = tx.storage.get_transaction(tx_conflict_id)
                            tx_conflict_meta = tx_conflict.get_metadata()
                            assert tx_conflict_meta.first_block is None
                            assert tx_conflict_meta.voided_by
                    self.context.transaction_algorithm.remove_voided_by(tx, tx.hash)
                    tx_meta.voided_by = None
                    self.context.save(tx)
            tx_meta.nc_execution = NCExecutionState.PENDING
            nc_calls.append(tx)

        if not nc_calls:
            meta.nc_block_root_id = block_root_id
            self.context.save(block)
            return

        nc_sorted_calls = self.context.consensus.nc_calls_sorter(block, nc_calls)
        block_storage = self.context.consensus.nc_storage_factory.get_block_storage(block_root_id)
        seed_hasher = hashlib.sha256(block.hash)

        for tx in nc_sorted_calls:
            seed_hasher.update(tx.hash)
            seed_hasher.update(block_storage.get_root_id())

            tx_meta = tx.get_metadata()
            if tx_meta.voided_by:
                # Skip voided transactions. This might happen if a previous tx in nc_calls fails and
                # mark this tx as voided.
                tx_meta.nc_execution = NCExecutionState.SKIPPED
                self.context.save(tx)
                # Update seqnum even for skipped nano transactions.
                nc_header = tx.get_nano_header()
                seqnum = block_storage.get_address_seqnum(Address(nc_header.nc_address))
                if nc_header.nc_seqnum > seqnum:
                    block_storage.set_address_seqnum(Address(nc_header.nc_address), nc_header.nc_seqnum)
                continue

            runner = self._runner_factory.create(block_storage=block_storage, seed=seed_hasher.digest())
            exception_and_tb: tuple[NCFail, str] | None = None
            token_dict = tx.get_complete_token_info(block_storage)
            should_verify_sum_after_execution = any(token_info.version is None for token_info in token_dict.values())

            try:
                runner.execute_from_tx(tx)

                # after the execution we have the latest state in the storage
                # and at this point no tokens pending creation
                if should_verify_sum_after_execution:
                    self._verify_sum_after_execution(tx, block_storage)

            except NCFail as e:
                kwargs: dict[str, Any] = {}
                if tx.name:
                    kwargs['__name'] = tx.name
                if self.nc_exec_fail_trace:
                    kwargs['exc_info'] = True
                self.log.info(
                    'nc execution failed',
                    tx=tx.hash.hex(),
                    error=repr(e),
                    cause=repr(e.__cause__),
                    **kwargs,
                )
                exception_and_tb = e, traceback.format_exc()
                self.mark_as_nc_fail_execution(tx)
            else:
                tx_meta.nc_execution = NCExecutionState.SUCCESS
                self.context.save(tx)
                # TODO Avoid calling multiple commits for the same contract. The best would be to call the commit
                #      method once per contract per block, just like we do for the block_storage. This ensures we will
                #      have a clean database with no orphan nodes.
                runner.commit()

                # Update metadata.
                self.nc_update_metadata(tx, runner)

                # Update indexes. This must be after metadata is updated.
                assert tx.storage is not None
                assert tx.storage.indexes is not None
                tx.storage.indexes.handle_contract_execution(tx)

                # Pubsub event to indicate execution success
                self.context.nc_exec_success.append(tx)

                # We only emit events when the nc is successfully executed.
                assert self.context.nc_events is not None
                last_call_info = runner.get_last_call_info()
                events_list = last_call_info.nc_logger.__events__
                self.context.nc_events.append((tx, events_list))

                # Store events in transaction metadata
                if events_list:
                    tx_meta.nc_events = [(event.nc_id, event.data) for event in events_list]
                    self.context.save(tx)
            finally:
                # We save logs regardless of whether the nc successfully executed.
                self._nc_log_storage.save_logs(tx, runner.get_last_call_info(), exception_and_tb)

        # Save block state root id. If nothing happens, it should be the same as its block parent.
        block_storage.commit()
        assert block_storage.get_root_id() is not None
        meta.nc_block_root_id = block_storage.get_root_id()
        self.context.save(block)

        for tx in nc_calls:
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

    def _verify_sum_after_execution(self, tx: Transaction, block_storage: NCBlockStorage) -> None:
        from hathor import NCFail
        from hathor.verification.transaction_verifier import TransactionVerifier
        try:
            token_dict = tx.get_complete_token_info(block_storage)
            TransactionVerifier.verify_sum(self._settings, token_dict)
        except TokenNotFound as e:
            # At this point, any nonexistent token would have made a prior validation fail. For example, if there
            # was a withdrawal of a nonexistent token, it would have failed in the balance validation before.
            raise AssertionError from e
        except Exception as e:
            raise NCFail from e

    def nc_update_metadata(self, tx: Transaction, runner: 'Runner') -> None:
        from hathor.nanocontracts.runner.call_info import CallType

        meta = tx.get_metadata()
        assert meta.nc_execution == NCExecutionState.SUCCESS
        call_info = runner.get_last_call_info()
        assert call_info.calls is not None
        nc_calls = [
            MetaNCCallRecord.from_call_record(call)
            for call in call_info.calls if call.type == CallType.PUBLIC
        ]

        # Update metadata.
        assert meta.nc_calls is None
        meta.nc_calls = nc_calls
        self.context.save(tx)

    def mark_as_nc_fail_execution(self, tx: Transaction) -> None:
        """Mark that a transaction failed execution. It also propagates its voidedness through the DAG of funds."""
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        assert tx.storage is not None
        tx_meta = tx.get_metadata()
        tx_meta.add_voided_by(NC_EXECUTION_FAIL_ID)
        tx_meta.nc_execution = NCExecutionState.FAILURE
        self.context.save(tx)
        self.context.transaction_algorithm.add_voided_by(tx,
                                                         tx.hash,
                                                         is_dag_verifications=False)
