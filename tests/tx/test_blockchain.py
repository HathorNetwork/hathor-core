from itertools import chain

from hathor.transaction import sum_weights
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest
from tests.utils import add_new_blocks, add_new_transactions


class BlockchainTestCase(unittest.TestCase):
    """
    Thus, there are eight cases to be handled when a new block arrives, which are:
    (i)    Single best chain, connected to the head of the best chain
    (ii)   Single best chain, connected to the tail of the best chain
    (iii)  Single best chain, connected to the head of a side chain
    (iv)   Single best chain, connected to the tail of a side chain
    (v)    Multiple best chains, connected to the head of a best chain
    (vi)   Multiple best chains, connected to the tail of a best chain
    (vii)  Multiple best chains, connected to the head of a side chain
    (viii) Multiple best chains, connected to the tail of a side chain
    """
    def setUp(self):
        super().setUp()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_single_chain(self):
        """ All new blocks belong to case (i).
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = self.genesis_blocks[0].weight
        for tx in self.genesis_txs:
            score = sum_weights(score, tx.weight)

        # Mine 50 blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 50, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata(force_reload=True)
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 30, advance_clock=15)
        for tx in txs:
            score = sum_weights(score, tx.weight)

        # Mine more 50 blocks in a row with no transactions between them
        blocks = add_new_blocks(manager, 50)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)
            self.assertAlmostEqual(manager.consensus_algorithm.block_algorithm.calculate_score(block), meta.score)

        # Mine more 15 blocks with 10 transactions between each block
        for _ in range(15):
            txs = add_new_transactions(manager, 10, advance_clock=15)
            for tx in txs:
                score = sum_weights(score, tx.weight)

            blocks = add_new_blocks(manager, 1)
            for i, block in enumerate(blocks):
                meta = block.get_metadata()
                score = sum_weights(score, block.weight)
                self.assertAlmostEqual(score, meta.score)
                self.assertAlmostEqual(manager.consensus_algorithm.block_algorithm.calculate_score(block), meta.score)

    def test_single_fork_not_best(self):
        """ New blocks belong to cases (i), (ii), (iii), and (iv).
        The best chain never changes. All other chains are side chains.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = self.genesis_blocks[0].weight
        for tx in self.genesis_txs:
            score = sum_weights(score, tx.weight)

        # Mine 5 blocks in a row with no transactions
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs:
            score = sum_weights(score, tx.weight)

        # Mine 1 blocks
        blocks = add_new_blocks(manager, 1, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Generate a block which will be a fork in the middle of the chain
        # Change the order of the transactions to change the hash
        fork_block1 = manager.generate_mining_block()
        fork_block1.parents = [fork_block1.parents[0]] + fork_block1.parents[:0:-1]
        fork_block1.resolve()
        fork_block1.verify()

        # Mine 8 blocks in a row
        blocks = add_new_blocks(manager, 8, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Fork block must have the same parents as blocks[0] as well as the same score
        self.assertEqual(set(blocks[0].parents), set(fork_block1.parents))

        # Propagate fork block.
        # This block belongs to case (ii).
        self.assertTrue(manager.propagate_tx(fork_block1))
        fork_meta1 = fork_block1.get_metadata()
        self.assertEqual(fork_meta1.voided_by, {fork_block1.hash})

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs:
            score = sum_weights(score, tx.weight)

        # Mine 5 blocks in a row
        # These blocks belong to case (i).
        blocks = add_new_blocks(manager, 5, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 2, advance_clock=15)
        for tx in txs:
            score = sum_weights(score, tx.weight)

        # Propagate a block connected to the voided chain
        # These blocks belongs to case (iii).
        sidechain1 = add_new_blocks(manager, 3, parent_block_hash=fork_block1.hash)
        for block in sidechain1:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 2, advance_clock=15)
        for tx in txs:
            score = sum_weights(score, tx.weight)

        # Propagate a block connected to the voided chain
        # This block belongs to case (iv).
        fork_block3 = manager.generate_mining_block(parent_block_hash=fork_block1.hash)
        fork_block3.resolve()
        fork_block3.verify()
        self.assertTrue(manager.propagate_tx(fork_block3))
        fork_meta3 = fork_block3.get_metadata()
        self.assertEqual(fork_meta3.voided_by, {fork_block3.hash})

        # dot = manager.tx_storage.graphviz(format='pdf')
        # dot.render('test_fork')

    def test_multiple_forks(self):
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = self.genesis_blocks[0].weight
        for tx in self.genesis_txs:
            score = sum_weights(score, tx.weight)

        # Mine 5 blocks in a row with no transactions, case (i).
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs1 = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs1:
            score = sum_weights(score, tx.weight)

        # Mine 1 blocks, case (i).
        blocks = add_new_blocks(manager, 1, advance_clock=15)
        block_before_fork = blocks[0]
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        for tx in txs1:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, blocks[0].hash)

        # Add some transactions between blocks
        txs2 = add_new_transactions(manager, 3, advance_clock=15)
        for tx in txs2:
            score = sum_weights(score, tx.weight)

        # Mine 5 blocks in a row, case (i).
        blocks = add_new_blocks(manager, 5, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score = sum_weights(score, block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Mine 4 blocks, starting a fork.
        # All these blocks belong to case (ii).
        sidechain = add_new_blocks(manager, 4, advance_clock=15, parent_block_hash=blocks[0].parents[0])

        # Fork block must have the same parents as blocks[0] as well as the same score
        self.assertEqual(set(blocks[0].parents), set(sidechain[0].parents))

        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, None)

        for block in sidechain:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Propagate a block connected to the voided chain, case (iii).
        fork_block2 = manager.generate_mining_block(parent_block_hash=sidechain[-1].hash)
        fork_block2.resolve()
        fork_block2.verify()
        self.assertTrue(manager.propagate_tx(fork_block2))
        sidechain.append(fork_block2)

        # Now, both chains have the same score.
        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in sidechain:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for tx in txs1:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, block_before_fork.hash)

        for tx in txs2:
            meta = tx.get_metadata(force_reload=True)
            self.assertIsNone(meta.first_block)

        # Mine 1 block, starting another fork.
        # This block belongs to case (vi).
        sidechain2 = add_new_blocks(manager, 1, advance_clock=15, parent_block_hash=sidechain[0].hash)

        for block in sidechain2:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Mine 2 more blocks in the new fork.
        # These blocks belong to case (vii).
        sidechain2 += add_new_blocks(manager, 2, advance_clock=15, parent_block_hash=sidechain2[-1].hash)

        for block in sidechain2:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Mine 1 block, starting another fork from sidechain2.
        # This block belongs to case (viii).
        sidechain3 = add_new_blocks(manager, 1, advance_clock=15, parent_block_hash=sidechain2[-2].hash)

        for block in sidechain3:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Propagate a block connected to the side chain, case (v).
        fork_block3 = manager.generate_mining_block(parent_block_hash=fork_block2.hash)
        fork_block3.resolve()
        fork_block3.verify()
        self.assertTrue(manager.propagate_tx(fork_block3))
        sidechain.append(fork_block3)

        # The side chains have exceeded the score (after it has the same score)
        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in sidechain:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, None)

        for tx in txs2:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, sidechain[0].hash)

        # Propagate a block connected to the side chain, case (v).
        # Another side chain has direcly exceeded the best score.
        fork_block4 = manager.generate_mining_block(parent_block_hash=sidechain3[-1].hash)
        fork_block4.weight = 10
        fork_block4.resolve()
        fork_block4.verify()
        self.assertTrue(manager.propagate_tx(fork_block4))
        sidechain3.append(fork_block4)

        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in sidechain[1:]:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in sidechain2[-1:]:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in chain(sidechain[:1], sidechain2[:-1], sidechain3):
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, None)

        for tx in txs2:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, sidechain[0].hash)

        # dot = manager.tx_storage.graphviz(format='pdf')
        # dot.render('test_fork')


if __name__ == '__main__':
    unittest.main()
