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
from typing import TYPE_CHECKING, Any, Iterable, Optional

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.util import classproperty
from hathor.utils.weight import weight_to_work

if TYPE_CHECKING:
    from hathor.consensus.context import ConsensusAlgorithmContext

logger = get_logger()

_base_transaction_log = logger.new()


class BlockConsensusAlgorithm:
    """Implement the consensus algorithm for blocks."""

    def __init__(self, context: 'ConsensusAlgorithmContext') -> None:
        self._settings = get_global_settings()
        self.context = context

    @classproperty
    def log(cls) -> Any:
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

        storage = block.storage
        assert storage.indexes is not None

        # Union of voided_by of parents
        voided_by: set[bytes] = self.union_voided_by_from_parents(block)

        # Update accumulated weight of the transactions voiding us.
        assert block.hash not in voided_by
        for h in voided_by:
            tx = storage.get_transaction(h)
            tx_meta = tx.get_metadata()
            tx_meta.accumulated_weight += weight_to_work(block.weight)
            self.context.save(tx)

        # Check conflicts of the transactions voiding us.
        for h in voided_by:
            tx = storage.get_transaction(h)
            if not tx.is_block:
                assert isinstance(tx, Transaction)
                self.context.transaction_algorithm.check_conflicts(tx)

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
                storage.indexes.height.add_new(block.get_height(), block.hash, block.timestamp)
                storage.update_best_block_tips_cache([block.hash])
            # The following assert must be true, but it is commented out for performance reasons.
            if self._settings.SLOW_ASSERTS:
                assert len(storage.get_best_block_tips(skip_cache=True)) == 1
        else:
            # Resolve all other cases, but (i).
            log = self.log.new(block=block.hash_hex)
            log.debug('this block is not the head of the bestchain',
                      is_connected_to_the_head=is_connected_to_the_head,
                      is_connected_to_the_best_chain=is_connected_to_the_best_chain)

            # First, void this block.
            # We need to void this block first, because otherwise it would always be one of the heads.
            self.mark_as_voided(block, skip_remove_first_block_markers=True)

            # Get the score of the best chains.
            head = storage.get_best_block()
            head_meta = head.get_metadata(force_reload=True)
            best_score = head_meta.score

            # Calculate the score.
            # We cannot calculate score before getting the heads.
            score = self.calculate_score(block)

            # Finally, check who the winner is.
            if score < best_score:
                # Just update voided_by from parents.
                self.update_voided_by_from_parents(block)

            else:
                # Either eveyone has the same score or there is a winner.

                valid_heads = []
                if not head_meta.voided_by:
                    valid_heads.append(head)

                # We must have at most one valid head.
                # Either we have a single best chain or all chains have already been voided.
                assert len(valid_heads) <= 1, 'We must never have more than one valid head'

                common_block = self._find_first_parent_in_best_chain(block)

                winner = False
                if score > best_score:
                    winner = True
                else:
                    min_hash: bytes = head.hash
                    if block.hash < min_hash:
                        winner = True

                if winner:
                    # Add voided_by to all heads.
                    self.add_voided_by_to_multiple_chains(block, [head], common_block)

                    # We have a new winner candidate.
                    self.update_score_and_mark_as_the_best_chain_if_possible(block)
                    # As `update_score_and_mark_as_the_best_chain_if_possible` may affect `voided_by`,
                    # we need to check that block is not voided.
                    meta = block.get_metadata()
                    height = block.get_height()
                    if not meta.voided_by:
                        self.log.debug('index new winner block', height=height, block=block.hash_hex)
                        # We update the height cache index with the new winner chain
                        storage.indexes.height.update_new_chain(height, block)
                        storage.update_best_block_tips_cache([block.hash])
                        # It is only a re-org if common_block not in heads
                        if common_block != head:
                            self.context.mark_as_reorg(common_block)

    def union_voided_by_from_parents(self, block: Block) -> set[bytes]:
        """Return the union of the voided_by of block's parents.

        It does not include the hash of blocks because the hash of blocks
        are not propagated through the chains. For further information, see
        the docstring of the ConsensusAlgorithm class.
        """
        voided_by: set[bytes] = set()
        for parent in block.get_parents():
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
                voided_by.update(self.context.consensus.filter_out_soft_voided_entries(parent, voided_by2))
        return voided_by

    def update_voided_by_from_parents(self, block: Block) -> bool:
        """Update block's metadata voided_by from parents.
        Return True if the block is voided and False otherwise."""
        assert block.storage is not None
        voided_by: set[bytes] = self.union_voided_by_from_parents(block)
        if voided_by:
            meta = block.get_metadata()
            if meta.voided_by:
                meta.voided_by.update(voided_by)
            else:
                meta.voided_by = voided_by.copy()
            self.context.save(block)
            block.storage.del_from_indexes(block, relax_assert=True)
            return True
        return False

    def add_voided_by_to_multiple_chains(self, block: Block, heads: list[Block], first_block: Block) -> None:
        # We need to go through all side chains because there may be non-voided blocks
        # that must be voided.
        # For instance, imagine two chains with intersection with both heads voided.
        # Now, a new chain starting in genesis reaches the same score. Then, the tail
        # of the two chains must be voided.
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
            head = storage.get_best_block()
            first_block = self._find_first_parent_in_best_chain(head)
            self.add_voided_by_to_multiple_chains(head, [block], first_block)
            assert head.hash != block.hash
            self.update_score_and_mark_as_the_best_chain_if_possible(head)

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

    def _find_first_parent_in_best_chain(self, block: Block) -> Block:
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
        self.context.save(block)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            self.context.transaction_algorithm.add_voided_by(tx, voided_hash)
        return True

    def remove_voided_by(self, block: Block, voided_hash: Optional[bytes] = None) -> bool:
        """ Remove a hash from its `meta.voided_by`. If `voided_hash` is None, it removes
        the block's own hash.
        """
        assert block.storage is not None

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
        self.context.save(block)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = storage.get_transaction(tx_hash)
            assert isinstance(tx, Transaction)
            self.context.transaction_algorithm.remove_voided_by(tx, voided_hash)
        return True

    def remove_first_block_markers(self, block: Block) -> None:
        """ Remove all `meta.first_block` pointing to this block.
        """
        assert block.storage is not None
        storage = block.storage

        from hathor.transaction.storage.traversal import BFSTimestampWalk
        bfs = BFSTimestampWalk(storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
        for tx in bfs.run(block, skip_root=True):
            if tx.is_block:
                bfs.skip_neighbors(tx)
                continue

            meta = tx.get_metadata()
            if meta.first_block != block.hash:
                bfs.skip_neighbors(tx)
                continue

            meta.first_block = None
            self.context.save(tx)

    def _score_block_dfs(self, block: BaseTransaction, used: set[bytes],
                         mark_as_best_chain: bool, newest_timestamp: int) -> int:
        """ Internal method to run a DFS. It is used by `calculate_score()`.
        """
        assert block.storage is not None
        assert block.is_block

        storage = block.storage

        from hathor.transaction import Block
        score = weight_to_work(block.weight)
        for parent in block.get_parents():
            if parent.is_block:
                assert isinstance(parent, Block)
                if parent.timestamp <= newest_timestamp:
                    meta = parent.get_metadata()
                    x = meta.score
                else:
                    x = self._score_block_dfs(parent, used, mark_as_best_chain, newest_timestamp)
                score += x

            else:
                from hathor.transaction.storage.traversal import BFSTimestampWalk
                bfs = BFSTimestampWalk(storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False)
                for tx in bfs.run(parent, skip_root=False):
                    assert tx.hash is not None
                    if tx.is_block:
                        bfs.skip_neighbors(tx)
                        continue

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
                        self.context.save(tx)

                    score += weight_to_work(tx.weight)

        # Always save the score when it is calculated.
        meta = block.get_metadata()
        if not meta.score:
            meta.score = score
            self.context.save(block)
        else:
            # The score of a block is immutable since the sub-DAG behind it is immutable as well.
            # Thus, if we have already calculated it, we just check the consistency of the calculation.
            # Unfortunately we may have to calculate it more than once when a new block arrives in a side
            # side because the `first_block` points only to the best chain.
            assert meta.score == score, \
                   'hash={} meta.score={} score={}'.format(block.hash.hex(), meta.score, score)

        return score

    def calculate_score(self, block: Block, *, mark_as_best_chain: bool = False) -> int:
        """ Calculate block's score, which is the accumulated work of the verified transactions and blocks.

        :param: mark_as_best_chain: If `True`, the transactions' will point `meta.first_block` to
                                    the blocks of the chain.
        """
        assert block.storage is not None
        if block.is_genesis:
            if mark_as_best_chain:
                meta = block.get_metadata()
                meta.score = weight_to_work(block.weight)
                self.context.save(block)
            return weight_to_work(block.weight)

        parent = self._find_first_parent_in_best_chain(block)
        newest_timestamp = parent.timestamp

        used: set[bytes] = set()
        return self._score_block_dfs(block, used, mark_as_best_chain, newest_timestamp)


class BlockConsensusAlgorithmFactory:
    def __call__(self, context: 'ConsensusAlgorithmContext') -> BlockConsensusAlgorithm:
        return BlockConsensusAlgorithm(context)
