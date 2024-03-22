# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.consensus.block_consensus import BlockConsensusAlgorithmFactory
from hathor.consensus.context import ConsensusAlgorithmContext
from hathor.consensus.transaction_consensus import TransactionConsensusAlgorithmFactory
from hathor.execution_manager import ExecutionManager
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.nanocontracts import NCStorageFactory

logger = get_logger()
cpu = get_cpu_profiler()

_base_transaction_log = logger.new()


class ConsensusAlgorithm:
    """Execute the consensus algorithm marking blocks and transactions as either executed or voided.

    The consensus algorithm uses the metadata voided_by to set whether a block or transaction is executed.
    If voided_by is empty, then the block or transaction is executed. Otherwise, it is voided.

    The voided_by stores which hashes are causing the voidance. The hashes may be from both blocks and
    transactions.

    The voidance propagates through the DAG of transactions. For example, if tx1 is voided and tx2 verifies
    tx1, then tx2 must be voided as well. Another example is that, if a block is not in the bestchain,
    any transaction spending one of the block's outputs is also voided.

    In the DAG of transactions, the voided_by of tx1 is always a subset of the voided_by of all transactions
    that verifies tx1 or spend one of tx1's outputs. The hash of tx1 may only be on its own voided_by when
    tx1 has conflicts and is not the winner.

    When a block is not in the bestchain, its voided_by contains its hash. This hash is also propagated
    through the transactions that spend one of its outputs.

    Differently from transactions, the hash of the blocks are not propagated through the voided_by of
    other blocks. For example, if b0 <- b1 <- b2 <- b3 is a side chain, i.e., not the best blockchain,
    then b0's voided_by contains b0's hash, b1's voided_by contains b1's hash, and so on. The hash of
    b0 will not be propagated to the voided_by of b1, b2, and b3.
    """

    def __init__(
        self,
        nc_storage_factory: 'NCStorageFactory',
        soft_voided_tx_ids: set[bytes],
        pubsub: PubSubManager,
        *,
        execution_manager: ExecutionManager
    ) -> None:
        self._settings = get_global_settings()
        self.log = logger.new()
        self._pubsub = pubsub
        self.nc_storage_factory = nc_storage_factory
        self.soft_voided_tx_ids = frozenset(soft_voided_tx_ids)
        self.block_algorithm_factory = BlockConsensusAlgorithmFactory()
        self.transaction_algorithm_factory = TransactionConsensusAlgorithmFactory()
        self._execution_manager = execution_manager

    def create_context(self) -> ConsensusAlgorithmContext:
        """Handy method to create a context that can be used to access block and transaction algorithms."""
        return ConsensusAlgorithmContext(self, self._pubsub)

    @cpu.profiler(key=lambda self, base: 'consensus!{}'.format(base.hash.hex()))
    def update(self, base: BaseTransaction) -> None:
        assert base.storage is not None
        assert base.storage.is_only_valid_allowed()
        meta = base.get_metadata()
        assert meta.validation.is_valid()
        try:
            self._unsafe_update(base)
        except BaseException:
            meta.add_voided_by(self._settings.CONSENSUS_FAIL_ID)
            assert base.storage is not None
            base.storage.save_transaction(base, only_metadata=True)
            self._execution_manager.crash_and_exit(reason=f'Consensus update failed for tx {base.hash_hex}')

    def _unsafe_update(self, base: BaseTransaction) -> None:
        """Run a consensus update with its own context, indexes will be updated accordingly."""
        from hathor.transaction import Block, Transaction

        # XXX: first make sure we can run the consensus update on this tx:
        meta = base.get_metadata()
        assert meta.voided_by is None or (self._settings.PARTIALLY_VALIDATED_ID not in meta.voided_by)
        assert meta.validation.is_fully_connected()

        # this context instance will live only while this update is running
        context = self.create_context()

        assert base.storage is not None
        storage = base.storage
        assert storage.indexes is not None
        best_height, best_tip = storage.indexes.height.get_height_tip()

        if isinstance(base, Transaction):
            context.transaction_algorithm.update_consensus(base)
        elif isinstance(base, Block):
            context.block_algorithm.update_consensus(base)
        else:
            raise NotImplementedError

        new_best_height, new_best_tip = storage.indexes.height.get_height_tip()
        if new_best_height < best_height:
            self.log.warn('height decreased, re-checking mempool', prev_height=best_height, new_height=new_best_height,
                          prev_block_tip=best_tip.hex(), new_block_tip=new_best_tip.hex())
            # XXX: this method will mark as INVALID all transactions in the mempool that became invalid because of a
            #      reward lock
            to_remove = storage.compute_transactions_that_became_invalid(new_best_height)
            if to_remove:
                self.log.warn('some transactions on the mempool became invalid and will be removed',
                              count=len(to_remove))
                # XXX: because transactions in `to_remove` are marked as invalid, we need this context to be able to
                #      remove them
                with storage.allow_invalid_context():
                    storage.remove_transactions(to_remove)
                for tx_removed in to_remove:
                    context.pubsub.publish(HathorEvents.CONSENSUS_TX_REMOVED, tx_hash=tx_removed.hash)

        # emit the reorg started event if needed
        if context.reorg_common_block is not None:
            old_best_block = base.storage.get_transaction(best_tip)
            assert isinstance(old_best_block, Block)
            new_best_block = base.storage.get_transaction(new_best_tip)
            reorg_size = old_best_block.get_height() - context.reorg_common_block.get_height()
            assert old_best_block != new_best_block
            assert reorg_size > 0
            context.pubsub.publish(HathorEvents.REORG_STARTED, old_best_height=best_height,
                                   old_best_block=old_best_block, new_best_height=new_best_height,
                                   new_best_block=new_best_block, common_block=context.reorg_common_block,
                                   reorg_size=reorg_size)

        # finally signal an index update for all affected transactions
        for tx_affected in _sorted_affected_txs(context.txs_affected):
            assert tx_affected.storage is not None
            assert tx_affected.storage.indexes is not None
            tx_affected.storage.indexes.update(tx_affected)
            context.pubsub.publish(HathorEvents.CONSENSUS_TX_UPDATE, tx=tx_affected)

        # and also emit the reorg finished event if needed
        if context.reorg_common_block is not None:
            context.pubsub.publish(HathorEvents.REORG_FINISHED)

    def filter_out_soft_voided_entries(self, tx: BaseTransaction, voided_by: set[bytes]) -> set[bytes]:
        if not (self.soft_voided_tx_ids & voided_by):
            return voided_by
        ret = set()
        for h in voided_by:
            if h == self._settings.SOFT_VOIDED_ID:
                continue
            if h == self._settings.CONSENSUS_FAIL_ID:
                continue
            if h == tx.hash:
                continue
            if h in self.soft_voided_tx_ids:
                continue
            assert tx.storage is not None
            tx3 = tx.storage.get_transaction(h)
            tx3_meta = tx3.get_metadata()
            tx3_voided_by: set[bytes] = tx3_meta.voided_by or set()
            if not (self.soft_voided_tx_ids & tx3_voided_by):
                ret.add(h)
        return ret


def _sorted_affected_txs(affected_txs: set[BaseTransaction]) -> list[BaseTransaction]:
    """
    Sort affected txs by voided first, then descending timestamp (reverse topological order).
    This is useful for generating Reliable Integration events.
    """
    def sorter(tx: BaseTransaction) -> tuple[bool, int]:
        meta = tx.get_metadata()
        is_voided = bool(meta.voided_by)

        return is_voided, not_none(tx.timestamp)

    return sorted(affected_txs, key=sorter, reverse=True)
