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

from itertools import chain
from typing import Iterable, List, Optional, Set, cast

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, Transaction, TxInput, sum_weights
from hathor.util import classproperty

logger = get_logger()
settings = HathorSettings()
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

    def __init__(self) -> None:
        self.block_algorithm = BlockConsensusAlgorithm(self)
        self.transaction_algorithm = TransactionConsensusAlgorithm(self)

    @cpu.profiler(key=lambda self, base: 'consensus!{}'.format(base.hash.hex()))
    def update(self, base: BaseTransaction) -> None:
        from hathor.transaction import Block, Transaction
        if isinstance(base, Transaction):
            self.transaction_algorithm.update_consensus(base)
        elif isinstance(base, Block):
            self.block_algorithm.update_consensus(base)
        else:
            raise NotImplementedError


class BlockConsensusAlgorithm:
    """Implement the consensus algorithm for blocks."""

    def __init__(self, consensus: ConsensusAlgorithm) -> None:
        self.consensus = consensus

    @classproperty
    def log(cls):
        """ This is a workaround because of a bug on structlog (or abc).

        See: https://github.com/hynek/structlog/issues/229
        """
        return _base_transaction_log

    def update_consensus(self, block: Block) -> None:
        self.update_voided_info(block)

    def update_voided_info(self, block: Block) -> None:
        """ This method is called only once when a new block arrives.

        The blockchain part of the DAG is a tree with the genesis block as the root.
        I'll say the a block A is connected to a block B when A verifies B, i.e., B is a parent of A.

        A chain is a sequence of connected blocks starting in a leaf and ending in the root, i.e., any path from a leaf
        to the root is a chain. Given a chain, its head is a leaf in the tree, and its tail is the sub-chain without
        the head.

        The best chain is a chain that has the highest score of all chains.

        The score of a block is calculated as the sum of the weights of all transactions and blocks both direcly and
        indirectly verified by the block. The score of a chain is defined as the score of its head.

        The side chains are the chains whose scores are smaller than the best chain's.
        The head of the side chains are always voided blocks.

        There are two possible states for the block chain:
        (i)  It has a single best chain, i.e., one chain has the highest score
        (ii) It has multiple best chains, i.e., two or more chains have the same score (and this score is the highest
             among the chains)

        When there are multiple best chains, I'll call them best chain candidates.

        The arrived block can be connected in four possible ways:
        (i)   To the head of a best chain
        (ii)  To the tail of the best chain
        (iii) To the head of a side chain
        (iv)  To the tail of a side chain

        Thus, there are eight cases to be handled when a new block arrives, which are:
        (i)    Single best chain, connected to the head of the best chain
        (ii)   Single best chain, connected to the tail of the best chain
        (iii)  Single best chain, connected to the head of a side chain
        (iv)   Single best chain, connected to the tail of a side chain
        (v)    Multiple best chains, connected to the head of a best chain
        (vi)   Multiple best chains, connected to the tail of a best chain
        (vii)  Multiple best chains, connected to the head of a side chain
        (viii) Multiple best chains, connected to the tail of a side chain

        Case (i) is trivial because the single best chain will remain as the best chain. So, just calculate the new
        score and that's it.

        Case (v) is also trivial. As there are multiple best chains and the new block is connected to the head of one
        of them, this will be the new winner. So, the blockchain state will change to a single best chain again.

        In the other cases, we must calculate the score and compare with the best score.

        When there are multiple best chains, all their heads will be voided.
        """
        assert block.weight > 0, 'This algorithm assumes that block\'s weight is always greater than zero'
        if not block.parents:
            assert block.is_genesis is True
            self.update_score_and_mark_as_the_best_chain(block)
            return

        assert block.storage is not None
        assert block.hash is not None

        storage = block.storage

        # Union of voided_by of parents
        voided_by: Set[bytes] = self.union_voided_by_from_parents(block)

        # Update accumulated weight of the transactions voiding us.
        assert block.hash not in voided_by
        for h in voided_by:
            tx = storage.get_transaction(h)
            tx_meta = tx.get_metadata()
            tx_meta.accumulated_weight = sum_weights(tx_meta.accumulated_weight, block.weight)
            storage.save_transaction(tx, only_metadata=True)

        # Check conflicts of the transactions voiding us.
        for h in voided_by:
            tx = storage.get_transaction(h)
            if not tx.is_block:
                assert isinstance(tx, Transaction)
                self.consensus.transaction_algorithm.check_conflicts(tx)

        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()
        assert block.hash in parent_meta.children

        # This method is called after the metadata of the parent is updated.
        # So, if the parent has only one child, it must be the current block.
        is_connected_to_the_head = bool(len(parent_meta.children) == 1)
        is_connected_to_the_best_chain = bool(not parent_meta.voided_by)

        if is_connected_to_the_head and is_connected_to_the_best_chain:
            # Case (i): Single best chain, connected to the head of the best chain
            self.update_score_and_mark_as_the_best_chain_if_possible(block)
            # As `update_score_and_mark_as_the_best_chain_if_possible` may affect `voided_by`,
            # we need to check that block is not voided.
            meta = block.get_metadata()
            if not meta.voided_by:
                storage._best_block_tips = [block.hash]
                storage.add_new_to_block_height_index(meta.height, block.hash)
            # The following assert must be true, but it is commented out for performance reasons.
            #     assert len(storage.get_best_block_tips(skip_cache=True)) == 1
        else:
            # Resolve all other cases, but (i).
            log = self.log.new(block=block.hash_hex)
            log.debug('this block is not the head of the bestchain',
                      is_connected_to_the_head=is_connected_to_the_head,
                      is_connected_to_the_best_chain=is_connected_to_the_best_chain)

            # First, void this block.
            self.mark_as_voided(block, skip_remove_first_block_markers=True)

            # Get the score of the best chains.
            # We need to void this block first, because otherwise it would always be one of the heads.
            heads = [cast(Block, storage.get_transaction(h)) for h in storage.get_best_block_tips()]
            best_score = None
            for head in heads:
                head_meta = head.get_metadata(force_reload=True)
                if best_score is None:
                    best_score = head_meta.score
                else:
                    # All heads must have the same score.
                    assert abs(best_score - head_meta.score) < 1e-10
            assert isinstance(best_score, (int, float))

            # Calculate the score.
            # We cannot calculate score before getting the heads.
            score = self.calculate_score(block)

            # Finally, check who the winner is.
            if score <= best_score - settings.WEIGHT_TOL:
                # Just update voided_by from parents.
                self.update_voided_by_from_parents(block)

            else:
                # Either eveyone has the same score or there is a winner.

                valid_heads = []
                for head in heads:
                    meta = head.get_metadata()
                    if not meta.voided_by:
                        valid_heads.append(head)

                # We must have at most one valid head.
                # Either we have a single best chain or all chains have already been voided.
                assert len(valid_heads) <= 1, 'We must never have more than one valid head'

                # Add voided_by to all heads.
                self.add_voided_by_to_multiple_chains(block, heads)

                if score >= best_score + settings.WEIGHT_TOL:
                    # We have a new winner candidate.
                    self.update_score_and_mark_as_the_best_chain_if_possible(block)
                    # As `update_score_and_mark_as_the_best_chain_if_possible` may affect `voided_by`,
                    # we need to check that block is not voided.
                    meta = block.get_metadata()
                    if not meta.voided_by:
                        storage._best_block_tips = [block.hash]
                        self.log.debug('index new winner block', height=meta.height, block=block.hash_hex)
                        # We update the height cache index with the new winner chain
                        storage.update_block_height_cache_new_chain(meta.height, block)
                else:
                    storage._best_block_tips = [blk.hash for blk in heads]
                    # XXX Is it safe to select one of the heads?
                    best_block = heads[0]
                    assert best_block.hash is not None
                    best_meta = best_block.get_metadata()
                    self.log.debug('index previous best block', height=best_meta.height, block=best_block.hash_hex)
                    storage.add_new_to_block_height_index(best_meta.height, best_block.hash)

        # Uncomment the following lines to check that the cache update is working properly.
        # You shouldn't run this test in production because it dampens performance.
        #     v = storage.get_best_block_tips(skip_cache=True)
        #     assert v == storage._best_block_tips

    def union_voided_by_from_parents(self, block: Block) -> Set[bytes]:
        """Return the union of the voided_by of block's parents.

        It does not include the hash of blocks because the hash of blocks
        are not propagated through the chains. For further information, see
        the docstring of the ConsensusAlgorithm class.
        """
        voided_by: Set[bytes] = set()
        for parent in block.get_parents():
            assert parent.hash is not None
            parent_meta = parent.get_metadata()
            voided_by2 = parent_meta.voided_by
            if voided_by2:
                if parent.is_block:
                    # We must go through the blocks because the voidance caused
                    # by a transaction must be sent ahead. For example, in the
                    # chain b0 <- b1 <- b2 <- b3, if a transaction voids b1, then
                    # it must also voids b2 and b3. But, we must ignore the hash of
                    # the blocks themselves.
                    voided_by2 = voided_by2.copy()
                    voided_by2.discard(parent.hash)
                voided_by.update(voided_by2)
        return voided_by

    def update_voided_by_from_parents(self, block: Block) -> bool:
        """Update block's metadata voided_by from parents.
        Return True if the block is voided and False otherwise."""
        assert block.storage is not None
        voided_by: Set[bytes] = self.union_voided_by_from_parents(block)
        if voided_by:
            meta = block.get_metadata()
            if meta.voided_by:
                meta.voided_by.update(voided_by)
            else:
                meta.voided_by = voided_by.copy()
            block.storage.save_transaction(block, only_metadata=True)
            block.storage.del_from_indexes(block, relax_assert=True)
            return True
        return False

    def add_voided_by_to_multiple_chains(self, block: Block, heads: List[Block]) -> None:
        # We need to go through all side chains because there may be non-voided blocks
        # that must be voided.
        # For instance, imagine two chains with intersection with both heads voided.
        # Now, a new chain starting in genesis reaches the same score. Then, the tail
        # of the two chains must be voided.
        first_block = self._find_first_parent_in_best_chain(block)
        for head in heads:
            while True:
                if head.timestamp <= first_block.timestamp:
                    break
                meta = head.get_metadata()
                if not (meta.voided_by and head.hash in meta.voided_by):
                    # Only mark as voided when it is non-voided.
                    self.mark_as_voided(head)
                # We have to go through the chain until the first parent in the best
                # chain because the head may be voided with part of the tail non-voided.
                head = head.get_block_parent()

    def update_score_and_mark_as_the_best_chain_if_possible(self, block: Block) -> None:
        """Update block's score and mark it as best chain if it is a valid consensus.
        If it is not, the block will be voided and the block with highest score will be set as
        best chain.
        """
        assert block.storage is not None
        self.update_score_and_mark_as_the_best_chain(block)
        self.remove_voided_by_from_chain(block)

        if self.update_voided_by_from_parents(block):
            storage = block.storage
            heads = [cast(Block, storage.get_transaction(h)) for h in storage.get_best_block_tips()]
            best_score = 0.0
            best_heads: List[Block]
            for head in heads:
                head_meta = head.get_metadata(force_reload=True)
                if head_meta.score <= best_score - settings.WEIGHT_TOL:
                    continue

                if head_meta.score >= best_score + settings.WEIGHT_TOL:
                    best_heads = [head]
                    best_score = head_meta.score
                else:
                    assert abs(best_score - head_meta.score) < 1e-10
                    best_heads.append(head)
            assert isinstance(best_score, (int, float)) and best_score > 0

            assert len(best_heads) > 0
            self.add_voided_by_to_multiple_chains(best_heads[0], [block])
            if len(best_heads) == 1:
                self.update_score_and_mark_as_the_best_chain_if_possible(best_heads[0])

    def update_score_and_mark_as_the_best_chain(self, block: Block) -> None:
        """ Update score and mark the chain as the best chain.
        Thus, transactions' first_block will point to the blocks in the chain.
        """
        self.calculate_score(block, mark_as_best_chain=True)

    def remove_voided_by_from_chain(self, block: Block) -> None:
        """ Remove voided_by from the chain. Now, it is the best chain.

        The blocks are visited from right to left (most recent to least recent).
        """
        while True:
            assert block.is_block
            success = self.remove_voided_by(block)
            if not success:
                break
            block = block.get_block_parent()

    def _find_first_parent_in_best_chain(self, block: Block) -> BaseTransaction:
        """ Find the first block in the side chain that is not voided, i.e., the block where the fork started.

        In the simple schema below, the best chain's blocks are O's, the side chain's blocks are I's, and the first
        valid block is the [O].

        O-O-O-O-[O]-O-O-O-O
                 |
                 +-I-I-I
        """
        assert block.storage is not None
        storage = block.storage

        assert len(block.parents) > 0, 'This should never happen because the genesis is always in the best chain'
        parent_hash = block.get_block_parent_hash()
        while True:
            parent = storage.get_transaction(parent_hash)
            assert isinstance(parent, Block)
            parent_meta = parent.get_metadata()
            if not parent_meta.voided_by:
                break
            assert len(parent.parents) > 0, 'This should never happen because the genesis is always in the best chain'
            parent_hash = parent.get_block_parent_hash()
        return parent

    def mark_as_voided(self, block: Block, *, skip_remove_first_block_markers: bool = False) -> None:
        """ Mark a block as voided. By default, it will remove the first block markers from
        `meta.first_block` of the transactions that point to it.
        """
        self.log.debug('block.mark_as_voided', block=block.hash_hex)
        if not skip_remove_first_block_markers:
            self.remove_first_block_markers(block)
        self.add_voided_by(block)

    def add_voided_by(self, block: Block, voided_hash: Optional[bytes] = None) -> bool:
        """ Add a new hash in its `meta.voided_by`. If `voided_hash` is None, it includes
        the block's own hash.
        """
        assert block.storage is not None
        assert block.hash is not None

        storage = block.storage

        if voided_hash is None:
            voided_hash = block.hash
        assert voided_hash is not None

        meta = block.get_metadata()
        if not meta.voided_by:
            meta.voided_by = set()
        if voided_hash in meta.voided_by:
            return False

        self.log.debug('add_voided_by', block=block.hash_hex, voided_hash=voided_hash.hex())

        meta.voided_by.add(voided_hash)
        storage.save_transaction(block, only_metadata=True)
        block.storage.del_from_indexes(block)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            self.consensus.transaction_algorithm.add_voided_by(tx, voided_hash)
        return True

    def remove_voided_by(self, block: Block, voided_hash: Optional[bytes] = None) -> bool:
        """ Remove a hash from its `meta.voided_by`. If `voided_hash` is None, it removes
        the block's own hash.
        """
        assert block.storage is not None
        assert block.hash is not None

        storage = block.storage

        if voided_hash is None:
            voided_hash = block.hash

        meta = block.get_metadata()
        if not meta.voided_by:
            return False
        if voided_hash not in meta.voided_by:
            return False

        self.log.debug('remove_voided_by', block=block.hash_hex, voided_hash=voided_hash.hex())

        meta.voided_by.remove(voided_hash)
        if not meta.voided_by:
            meta.voided_by = None
            block.storage.add_to_indexes(block)
        block.storage.save_transaction(block, only_metadata=True)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            self.consensus.transaction_algorithm.remove_voided_by(tx, voided_hash)
        return True

    def remove_first_block_markers(self, block: Block) -> None:
        """ Remove all `meta.first_block` pointing to this block.
        """
        assert block.storage is not None
        storage = block.storage

        from hathor.transaction.storage.traversal import BFSWalk
        bfs = BFSWalk(storage, is_dag_verifications=True, is_left_to_right=False)
        for tx in bfs.run(block, skip_root=True):
            if tx.is_block:
                bfs.skip_neighbors(tx)
                continue

            meta = tx.get_metadata()
            if meta.first_block != block.hash:
                bfs.skip_neighbors(tx)
                continue

            meta.first_block = None
            storage.save_transaction(tx, only_metadata=True)

    def _score_block_dfs(self, block: BaseTransaction, used: Set[bytes],
                         mark_as_best_chain: bool, newest_timestamp: int) -> float:
        """ Internal method to run a DFS. It is used by `calculate_score()`.
        """
        assert block.storage is not None
        assert block.hash is not None
        assert block.is_block

        storage = block.storage

        from hathor.transaction import Block
        score = block.weight
        for parent in block.get_parents():
            if parent.is_block:
                assert isinstance(parent, Block)
                if parent.timestamp <= newest_timestamp:
                    meta = parent.get_metadata()
                    x = meta.score
                else:
                    x = self._score_block_dfs(parent, used, mark_as_best_chain, newest_timestamp)
                score = sum_weights(score, x)

            else:
                from hathor.transaction.storage.traversal import BFSWalk
                bfs = BFSWalk(storage, is_dag_verifications=True, is_left_to_right=False)
                for tx in bfs.run(parent, skip_root=False):
                    assert tx.hash is not None
                    assert not tx.is_block

                    if tx.hash in used:
                        bfs.skip_neighbors(tx)
                        continue
                    used.add(tx.hash)

                    meta = tx.get_metadata()
                    if meta.first_block:
                        first_block = storage.get_transaction(meta.first_block)
                        if first_block.timestamp <= newest_timestamp:
                            bfs.skip_neighbors(tx)
                            continue

                    if mark_as_best_chain:
                        assert meta.first_block is None
                        meta.first_block = block.hash
                        storage.save_transaction(tx, only_metadata=True)

                    score = sum_weights(score, tx.weight)

        # Always save the score when it is calculated.
        meta = block.get_metadata()
        if not meta.score:
            meta.score = score
            storage.save_transaction(block, only_metadata=True)
        else:
            # The score of a block is immutable since the sub-DAG behind it is immutable as well.
            # Thus, if we have already calculated it, we just check the consistency of the calculation.
            # Unfortunately we may have to calculate it more than once when a new block arrives in a side
            # side because the `first_block` points only to the best chain.
            assert abs(meta.score - score) < 1e-10, \
                   'hash={} meta.score={} score={}'.format(block.hash.hex(), meta.score, score)

        return score

    def calculate_score(self, block: Block, *, mark_as_best_chain: bool = False) -> float:
        """ Calculate block's score, which is the accumulated work of the verified transactions and blocks.

        :param: mark_as_best_chain: If `True`, the transactions' will point `meta.first_block` to
                                    the blocks of the chain.
        """
        assert block.storage is not None
        if block.is_genesis:
            if mark_as_best_chain:
                meta = block.get_metadata()
                meta.score = block.weight
                block.storage.save_transaction(block, only_metadata=True)
            return block.weight

        parent = self._find_first_parent_in_best_chain(block)
        newest_timestamp = parent.timestamp

        used: Set[bytes] = set()
        return self._score_block_dfs(block, used, mark_as_best_chain, newest_timestamp)


class TransactionConsensusAlgorithm:
    """Implement the consensus algorithm for transactions."""

    def __init__(self, consensus: ConsensusAlgorithm) -> None:
        self.consensus = consensus

    @classproperty
    def log(cls):
        """ This is a workaround because of a bug on structlog (or abc).

        See: https://github.com/hynek/structlog/issues/229
        """
        return _base_transaction_log

    def update_consensus(self, tx: Transaction) -> None:
        self.mark_inputs_as_used(tx)
        self.update_voided_info(tx)
        self.set_conflict_twins(tx)

    def mark_inputs_as_used(self, tx: Transaction) -> None:
        """ Mark all its inputs as used
        """
        for txin in tx.inputs:
            self.mark_input_as_used(tx, txin)

    def mark_input_as_used(self, tx: Transaction, txin: TxInput) -> None:
        """ Mark a given input as used
        """
        assert tx.hash is not None
        assert tx.storage is not None

        spent_tx = tx.storage.get_transaction(txin.tx_id)
        spent_meta = spent_tx.get_metadata()
        spent_by = spent_meta.spent_outputs[txin.index]
        assert tx.hash not in spent_by

        # Update our meta.conflict_with.
        meta = tx.get_metadata()
        if spent_by:
            # We initially void ourselves. This conflict will be resolved later.
            if not meta.voided_by:
                meta.voided_by = {tx.hash}
            else:
                meta.voided_by.add(tx.hash)
            if meta.conflict_with:
                meta.conflict_with.extend(set(spent_by) - set(meta.conflict_with))
            else:
                meta.conflict_with = spent_by.copy()
        tx.storage.save_transaction(tx, only_metadata=True)

        for h in spent_by:
            # Update meta.conflict_with of our conflict transactions.
            conflict_tx = tx.storage.get_transaction(h)
            tx_meta = conflict_tx.get_metadata()
            if tx_meta.conflict_with:
                if tx.hash not in tx_meta.conflict_with:
                    # We could use a set instead of a list but it consumes ~2.15 times more of memory.
                    tx_meta.conflict_with.append(tx.hash)
            else:
                tx_meta.conflict_with = [tx.hash]
            tx.storage.save_transaction(conflict_tx, only_metadata=True)

        # Add ourselves to meta.spent_by of our input.
        spent_by.append(tx.hash)
        tx.storage.save_transaction(spent_tx, only_metadata=True)

    def set_conflict_twins(self, tx: Transaction) -> None:
        """ Get all transactions that conflict with self
            and check if they are also a twin of self
        """
        assert tx.storage is not None

        meta = tx.get_metadata()
        if not meta.conflict_with:
            return

        conflict_txs = [tx.storage.get_transaction(h) for h in meta.conflict_with]
        self.check_twins(tx, conflict_txs)

    def check_twins(self, tx: Transaction, transactions: Iterable[BaseTransaction]) -> None:
        """ Check if the tx has any twins in transactions list
            A twin tx is a tx that has the same inputs and outputs
            We add all the hashes of the twin txs in the metadata

        :param transactions: list of transactions to be checked if they are twins with self
        """
        assert tx.hash is not None
        assert tx.storage is not None

        # Getting tx metadata to save the new twins
        meta = tx.get_metadata()

        # Sorting inputs and outputs for easier validation
        sorted_inputs = sorted(tx.inputs, key=lambda x: (x.tx_id, x.index, x.data))
        sorted_outputs = sorted(tx.outputs, key=lambda x: (x.script, x.value))

        for candidate in transactions:
            assert candidate.hash is not None

            # If quantity of inputs is different, it's not a twin.
            if len(candidate.inputs) != len(tx.inputs):
                continue

            # If quantity of outputs is different, it's not a twin.
            if len(candidate.outputs) != len(tx.outputs):
                continue

            # If the hash is the same, it's not a twin.
            if candidate.hash == tx.hash:
                continue

            # Verify if all the inputs are the same
            equal = True
            for index, tx_input in enumerate(sorted(candidate.inputs, key=lambda x: (x.tx_id, x.index, x.data))):
                if (tx_input.tx_id != sorted_inputs[index].tx_id or tx_input.data != sorted_inputs[index].data
                        or tx_input.index != sorted_inputs[index].index):
                    equal = False
                    break

            # Verify if all the outputs are the same
            if equal:
                for index, tx_output in enumerate(sorted(candidate.outputs, key=lambda x: (x.script, x.value))):
                    if (tx_output.value != sorted_outputs[index].value
                            or tx_output.script != sorted_outputs[index].script):
                        equal = False
                        break

            # If everything is equal we add in both metadatas
            if equal:
                meta.twins.append(candidate.hash)
                tx_meta = candidate.get_metadata()
                tx_meta.twins.append(tx.hash)
                tx.storage.save_transaction(candidate, only_metadata=True)

        tx.storage.save_transaction(tx, only_metadata=True)

    def update_voided_info(self, tx: Transaction) -> None:
        """ This method should be called only once when the transactions is added to the DAG.
        """
        assert tx.hash is not None
        assert tx.storage is not None

        voided_by: Set[bytes] = set()

        # Union of voided_by of parents
        for parent in tx.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by:
                voided_by.update(parent_meta.voided_by)

        # Union of voided_by of inputs
        for txin in tx.inputs:
            spent_tx = tx.storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            if spent_meta.voided_by:
                voided_by.update(spent_meta.voided_by)

        # Update accumulated weight of the transactions voiding us.
        assert tx.hash not in voided_by
        for h in voided_by:
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_meta.accumulated_weight = sum_weights(tx2_meta.accumulated_weight, tx.weight)
            assert tx2.storage is not None
            tx2.storage.save_transaction(tx2, only_metadata=True)

        # Then, we add ourselves.
        meta = tx.get_metadata()
        assert not meta.voided_by or meta.voided_by == {tx.hash}
        assert meta.accumulated_weight == tx.weight
        if meta.conflict_with:
            voided_by.add(tx.hash)

        if voided_by:
            meta.voided_by = voided_by.copy()
            tx.storage.save_transaction(tx, only_metadata=True)
            tx.storage.del_from_indexes(tx)

        # Check conflicts of the transactions voiding us.
        for h in voided_by:
            if h == tx.hash:
                continue
            conflict_tx = tx.storage.get_transaction(h)
            if not conflict_tx.is_block:
                assert isinstance(conflict_tx, Transaction)
                self.check_conflicts(conflict_tx)

        # Finally, check our conflicts.
        meta = tx.get_metadata()
        if meta.voided_by == {tx.hash}:
            self.check_conflicts(tx)

    def check_conflicts(self, tx: Transaction) -> None:
        """ Check which transaction is the winner of a conflict, the remaining are voided.

        The verification is made for each input, and `self` is only marked as winner if it
        wins in all its inputs.
        """
        assert tx.hash is not None
        assert tx.storage is not None
        self.log.debug('tx.check_conflicts', tx=tx.hash_hex)

        meta = tx.get_metadata()
        if meta.voided_by != {tx.hash}:
            return

        # Filter the possible candidates to compare to tx.
        candidates: List[Transaction] = []
        for h in meta.conflict_with or []:
            conflict_tx = cast(Transaction, tx.storage.get_transaction(h))
            conflict_tx_meta = conflict_tx.get_metadata()
            if not conflict_tx_meta.voided_by or conflict_tx_meta.voided_by == {tx.hash}:
                candidates.append(conflict_tx)

        # Check whether we have the highest accumulated weight.
        # First with the voided transactions.
        is_highest = True
        for candidate in candidates:
            tx_meta = candidate.get_metadata()
            if tx_meta.voided_by:
                if tx_meta.accumulated_weight > meta.accumulated_weight:
                    is_highest = False
                    break
        if not is_highest:
            return

        # Then, with the executed transactions.
        tie_list = []
        for candidate in candidates:
            tx_meta = candidate.get_metadata()
            if not tx_meta.voided_by:
                candidate.update_accumulated_weight(stop_value=meta.accumulated_weight)
                tx_meta = candidate.get_metadata()
                d = tx_meta.accumulated_weight - meta.accumulated_weight
                if abs(d) < settings.WEIGHT_TOL:
                    tie_list.append(candidate)
                elif d > 0:
                    is_highest = False
                    break
        if not is_highest:
            return

        # If we got here, either it was a tie or we won.
        # So, let's void the candidates.
        for candidate in candidates:
            self.mark_as_voided(candidate)

        if not tie_list:
            # If it is not a tie, we won. \o/
            self.mark_as_winner(tx)

    def mark_as_winner(self, tx: Transaction) -> None:
        """ Mark a transaction as winner when it has a conflict and its aggregated weight
        is the greatest one.
        """
        assert tx.hash is not None
        self.log.debug('tx.mark_as_winner', tx=tx.hash_hex)
        meta = tx.get_metadata()
        assert bool(meta.conflict_with)  # FIXME: this looks like a runtime guarantee, MUST NOT be an assert
        self.remove_voided_by(tx, tx.hash)

    def remove_voided_by(self, tx: Transaction, voided_hash: bytes) -> bool:
        """ Remove a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        from hathor.transaction.storage.traversal import BFSWalk

        assert tx.hash is not None
        assert tx.storage is not None

        meta = tx.get_metadata()
        if not meta.voided_by:
            return False
        if voided_hash not in meta.voided_by:
            return False

        self.log.debug('remove_voided_by', tx=tx.hash_hex, voided_hash=voided_hash.hex())

        bfs = BFSWalk(tx.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        check_list: List[BaseTransaction] = []
        for tx2 in bfs.run(tx, skip_root=False):
            assert tx2.storage is not None

            meta = tx2.get_metadata()
            if not (meta.voided_by and voided_hash in meta.voided_by):
                bfs.skip_neighbors(tx2)
                continue
            if meta.voided_by:
                meta.voided_by.discard(voided_hash)
            if meta.voided_by == {tx2.hash}:
                check_list.append(tx2)
            tx2.storage.save_transaction(tx2, only_metadata=True)
            if not meta.voided_by:
                meta.voided_by = None
                tx.storage.add_to_indexes(tx2)

        from hathor.transaction import Transaction
        for tx2 in check_list:
            if not tx2.is_block:
                assert isinstance(tx2, Transaction)
                self.check_conflicts(tx2)
        return True

    def mark_as_voided(self, tx: Transaction) -> None:
        """ Mark a transaction as voided when it has a conflict and its aggregated weight
        is NOT the greatest one.
        """
        assert tx.hash is not None
        self.log.debug('tx.mark_as_voided', tx=tx.hash_hex)
        meta = tx.get_metadata()
        assert bool(meta.conflict_with)
        if meta.voided_by:
            assert tx.hash in meta.voided_by
            return
        self.add_voided_by(tx, tx.hash)

    def add_voided_by(self, tx: Transaction, voided_hash: bytes) -> bool:
        """ Add a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        assert tx.hash is not None
        assert tx.storage is not None

        meta = tx.get_metadata()
        if meta.voided_by and voided_hash in meta.voided_by:
            return False

        self.log.debug('add_voided_by', tx=tx.hash_hex, voided_hash=voided_hash.hex())

        from hathor.transaction.storage.traversal import BFSWalk
        bfs = BFSWalk(tx.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        check_list: List[Transaction] = []
        for tx2 in bfs.run(tx, skip_root=False):
            assert tx2.storage is not None
            assert tx2.hash is not None
            meta2 = tx2.get_metadata()

            if tx2.is_block:
                assert isinstance(tx2, Block)
                self.consensus.block_algorithm.mark_as_voided(tx2)

            assert not meta2.voided_by or voided_hash not in meta2.voided_by
            if tx2.hash != tx.hash and meta2.conflict_with and not meta2.voided_by:
                check_list.extend(cast(Transaction, tx2.storage.get_transaction(h)) for h in meta2.conflict_with)
            if meta2.voided_by:
                meta2.voided_by.add(voided_hash)
            else:
                meta2.voided_by = {voided_hash}
            if meta2.conflict_with:
                meta2.voided_by.add(tx2.hash)
                # All voided transactions with conflicts must have their accumulated weight calculated.
                tx2.update_accumulated_weight(save_file=False)
            tx2.storage.save_transaction(tx2, only_metadata=True)
            tx2.storage.del_from_indexes(tx2, relax_assert=True)

        for tx2 in check_list:
            self.check_conflicts(tx2)
        return True
