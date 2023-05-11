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

from typing import Set

from structlog import get_logger

from hathor.conf import constants
from hathor.consensus.block_consensus import BlockConsensusAlgorithmFactory
from hathor.consensus.context import ConsensusAlgorithmContext
from hathor.consensus.transaction_consensus import TransactionConsensusAlgorithmFactory
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction

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

    def __init__(self, soft_voided_tx_ids: Set[bytes], pubsub: PubSubManager) -> None:
        self.log = logger.new()
        self._pubsub = pubsub
        self.soft_voided_tx_ids = frozenset(soft_voided_tx_ids)
        self.block_algorithm_factory = BlockConsensusAlgorithmFactory()
        self.transaction_algorithm_factory = TransactionConsensusAlgorithmFactory()

    def create_context(self) -> ConsensusAlgorithmContext:
        """Handy method to create a context that can be used to access block and transaction algorithms."""
        return ConsensusAlgorithmContext(self, self._pubsub)

    @cpu.profiler(key=lambda self, base: 'consensus!{}'.format(base.hash.hex()))
    def update(self, base: BaseTransaction) -> None:
        try:
            self._unsafe_update(base)
        except Exception:
            meta = base.get_metadata()
            meta.add_voided_by(constants.CONSENSUS_FAIL_ID)
            assert base.storage is not None
            base.storage.save_transaction(base, only_metadata=True)
            raise

    def _unsafe_update(self, base: BaseTransaction) -> None:
        """Run a consensus update with its own context, indexes will be updated accordingly."""
        from hathor.transaction import Block, Transaction

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
            to_remove = storage.get_transactions_that_became_invalid()
            if to_remove:
                self.log.warn('some transactions on the mempool became invalid and will be removed',
                              count=len(to_remove))
                storage.remove_transactions(to_remove)
                for tx_removed in to_remove:
                    context.pubsub.publish(HathorEvents.CONSENSUS_TX_REMOVED, tx_hash=tx_removed.hash)

        # emit the reorg started event if needed
        if context.reorg_common_block is not None:
            old_best_block = base.storage.get_transaction(best_tip)
            new_best_block = base.storage.get_transaction(new_best_tip)
            old_best_block_meta = old_best_block.get_metadata()
            common_block_meta = context.reorg_common_block.get_metadata()
            reorg_size = old_best_block_meta.height - common_block_meta.height
            assert old_best_block != new_best_block
            assert reorg_size > 0
            context.pubsub.publish(HathorEvents.REORG_STARTED, old_best_height=best_height,
                                   old_best_block=old_best_block, new_best_height=new_best_height,
                                   new_best_block=new_best_block, common_block=context.reorg_common_block,
                                   reorg_size=reorg_size)

        # finally signal an index update for all affected transactions
        for tx_affected in context.txs_affected:
            assert tx_affected.storage is not None
            assert tx_affected.storage.indexes is not None
            tx_affected.storage.indexes.update(tx_affected)
            context.pubsub.publish(HathorEvents.CONSENSUS_TX_UPDATE, tx=tx_affected)

        # and also emit the reorg finished event if needed
        if context.reorg_common_block is not None:
            context.pubsub.publish(HathorEvents.REORG_FINISHED)

    def filter_out_soft_voided_entries(self, tx: BaseTransaction, voided_by: Set[bytes]) -> Set[bytes]:
        if not (self.soft_voided_tx_ids & voided_by):
            return voided_by
        ret = set()
        for h in voided_by:
            if h == constants.SOFT_VOIDED_ID:
                continue
            if h == tx.hash:
                continue
            if h in self.soft_voided_tx_ids:
                continue
            assert tx.storage is not None
            tx3 = tx.storage.get_transaction(h)
            tx3_meta = tx3.get_metadata()
            tx3_voided_by: Set[bytes] = tx3_meta.voided_by or set()
            if not (self.soft_voided_tx_ids & tx3_voided_by):
                ret.add(h)
        return ret
