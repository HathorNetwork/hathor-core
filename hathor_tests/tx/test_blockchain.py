from itertools import chain

from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.simulator.utils import add_new_blocks
from hathor.utils.weight import weight_to_work
from hathor_tests import unittest
from hathor_tests.utils import add_new_transactions


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
        self.tx_storage = self.create_tx_storage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]
        self.daa = DifficultyAdjustmentAlgorithm(settings=self._settings)

    def test_single_chain(self):
        """ All new blocks belong to case (i).
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = weight_to_work(self.genesis_blocks[0].weight)
        for tx in self.genesis_txs:
            score += weight_to_work(tx.weight)

        # Mine 100 blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 100, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata(force_reload=True)
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 30, advance_clock=15)
        for tx in txs:
            score += weight_to_work(tx.weight)

        # Mine 50 more blocks in a row with no transactions between them
        blocks = add_new_blocks(manager, 50)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)
            consensus_context = manager.consensus_algorithm.create_context()
            self.assertAlmostEqual(consensus_context.block_algorithm.calculate_score(block), meta.score)

        # Mine 15 more blocks with 10 transactions between each block
        for _ in range(15):
            txs = add_new_transactions(manager, 10, advance_clock=15)
            for tx in txs:
                score += weight_to_work(tx.weight)

            blocks = add_new_blocks(manager, 1)
            for i, block in enumerate(blocks):
                meta = block.get_metadata()
                score += weight_to_work(block.weight)
                self.assertAlmostEqual(score, meta.score)
                consensus_context = manager.consensus_algorithm.create_context()
                self.assertAlmostEqual(consensus_context.block_algorithm.calculate_score(block), meta.score)

        self.assertConsensusValid(manager)

    def test_single_fork_not_best(self):
        """ New blocks belong to cases (i), (ii), (iii), and (iv).
        The best chain never changes. All other chains are side chains.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = weight_to_work(self.genesis_blocks[0].weight)
        for tx in self.genesis_txs:
            score += weight_to_work(tx.weight)

        # Mine 30 blocks in a row with no transactions
        blocks = add_new_blocks(manager, 30, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs:
            score += weight_to_work(tx.weight)

        # Mine 1 blocks
        blocks = add_new_blocks(manager, 1, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Generate a block which will be a fork in the middle of the chain
        # Change the order of the transactions to change the hash
        fork_block1 = manager.generate_mining_block()
        fork_block1.parents = [fork_block1.parents[0]] + fork_block1.parents[:0:-1]
        manager.cpu_mining_service.resolve(fork_block1)

        # Mine 8 blocks in a row
        blocks = add_new_blocks(manager, 8, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Propagate fork block.
        # This block belongs to case (ii).
        self.assertTrue(manager.propagate_tx(fork_block1))
        fork_meta1 = fork_block1.get_metadata()
        self.assertEqual(fork_meta1.voided_by, {fork_block1.hash})

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs:
            score += weight_to_work(tx.weight)

        # Mine 5 blocks in a row
        # These blocks belong to case (i).
        blocks = add_new_blocks(manager, 5, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 2, advance_clock=15)
        for tx in txs:
            score += weight_to_work(tx.weight)

        # Propagate a block connected to the voided chain
        # These blocks belongs to case (iii).
        sidechain1 = add_new_blocks(manager, 3, parent_block_hash=fork_block1.hash)
        for block in sidechain1:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 2, advance_clock=15)
        for tx in txs:
            score += weight_to_work(tx.weight)

        # Propagate a block connected to the voided chain
        # This block belongs to case (iv).
        fork_block3 = manager.generate_mining_block(parent_block_hash=fork_block1.hash)
        manager.cpu_mining_service.resolve(fork_block3)
        self.assertTrue(manager.propagate_tx(fork_block3))
        fork_meta3 = fork_block3.get_metadata()
        self.assertEqual(fork_meta3.voided_by, {fork_block3.hash})

        self.assertConsensusValid(manager)

    def test_multiple_forks(self):
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # The initial score is the sum of the genesis
        score = weight_to_work(self.genesis_blocks[0].weight)
        for tx in self.genesis_txs:
            score += weight_to_work(tx.weight)

        # Mine 30 blocks in a row with no transactions, case (i).
        blocks = add_new_blocks(manager, 30, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Add some transactions between blocks
        txs1 = add_new_transactions(manager, 5, advance_clock=15)
        for tx in txs1:
            score += weight_to_work(tx.weight)

        # Mine 1 blocks, case (i).
        blocks = add_new_blocks(manager, 1, advance_clock=15)
        block_before_fork = blocks[0]
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        for tx in txs1:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, blocks[0].hash)

        # Add some transactions between blocks
        txs2 = add_new_transactions(manager, 3, advance_clock=15)
        for tx in txs2:
            score += weight_to_work(tx.weight)

        # Mine 5 blocks in a row, case (i).
        blocks = add_new_blocks(manager, 5, advance_clock=15)
        for i, block in enumerate(blocks):
            meta = block.get_metadata()
            score += weight_to_work(block.weight)
            self.assertAlmostEqual(score, meta.score)

        # Mine 4 blocks, starting a fork.
        # All these blocks belong to case (ii).
        sidechain = add_new_blocks(manager, 4, advance_clock=15, parent_block_hash=blocks[0].parents[0])

        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, None)

        for block in sidechain:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        # Propagate a block connected to the voided chain, case (iii).
        fork_block2 = manager.generate_mining_block(parent_block_hash=sidechain[-1].hash)
        manager.cpu_mining_service.resolve(fork_block2)
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
        manager.cpu_mining_service.resolve(fork_block3)
        self.assertTrue(manager.propagate_tx(fork_block3))
        sidechain.append(fork_block3)

        # The side chains have exceeded the score (after it has the same score)
        for block in blocks:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, {block.hash})

        for block in sidechain:
            meta = block.get_metadata(force_reload=True)
            self.assertEqual(meta.voided_by, None)

        # from hathor.graphviz import GraphvizVisualizer
        # dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
        # dot.render('dot0')

        for tx in txs2:
            meta = tx.get_metadata(force_reload=True)
            self.assertEqual(meta.first_block, sidechain[0].hash)

        # Propagate a block connected to the side chain, case (v).
        # Another side chain has direcly exceeded the best score.
        fork_block4 = manager.generate_mining_block(parent_block_hash=sidechain3[-1].hash)
        fork_block4.weight = 10
        manager.cpu_mining_service.resolve(fork_block4)
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

        self.assertConsensusValid(manager)

    def test_block_height(self):
        genesis_block = self.genesis_blocks[0]
        self.assertEqual(genesis_block.static_metadata.height, 0)

        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine 50 blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 50, advance_clock=15)

        for i, block in enumerate(blocks):
            expected_height = i + 1
            self.assertEqual(block.static_metadata.height, expected_height)

    def test_tokens_issued_per_block(self):
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)
        # this test is pretty dumb in that it test every possible height until halving has long stopped
        initial_reward = self._settings.INITIAL_TOKENS_PER_BLOCK
        final_reward = self._settings.MINIMUM_TOKENS_PER_BLOCK
        expected_reward = initial_reward
        height = 1
        # check that there are BLOCKS_PER_HALVING with each reward, starting at the first rewardable block (height=1)
        for _i_halving in range(0, self._settings.MAXIMUM_NUMBER_OF_HALVINGS):
            for _i_block in range(0, self._settings.BLOCKS_PER_HALVING):
                reward = manager.get_tokens_issued_per_block(height)
                self.assertEqual(reward, expected_reward, f'reward at height {height}')
                height += 1
            expected_reward /= 2
        self.assertEqual(expected_reward, final_reward)
        # check that halving stops, for at least two "halving rounds"
        for _i_block in range(0, 2 * self._settings.BLOCKS_PER_HALVING):
            reward = manager.get_tokens_issued_per_block(height)
            self.assertEqual(reward, expected_reward, f'reward at height {height}')
            height += 1

    def test_block_rewards(self):
        # even dumber test that only check if manager.get_tokens_issued_per_block was used correctly for a really large
        # number of blocks, probably not worth running all the time
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)
        block_count = (self._settings.MAXIMUM_NUMBER_OF_HALVINGS + 1) * self._settings.BLOCKS_PER_HALVING
        blocks = add_new_blocks(manager, block_count, advance_clock=block_count * 30)
        for block in blocks:
            outputs = block.outputs
            self.assertEqual(len(outputs), 1)
            output = outputs[0]
            height = block.static_metadata.height
            self.assertEqual(output.value, manager.get_tokens_issued_per_block(height))

    def test_daa_sanity(self):
        # sanity test the DAA
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)
        manager.daa.TEST_MODE = TestMode.DISABLED
        N = self._settings.BLOCK_DIFFICULTY_N_BLOCKS
        T = self._settings.AVG_TIME_BETWEEN_BLOCKS
        manager.avg_time_between_blocks = T
        # stabilize weight on 2 and lower the minimum to 1, so it can vary around 2
        manager.min_block_weight = 2
        add_new_blocks(manager, N * 2, advance_clock=T)
        manager.min_block_weight = 1
        for i in range(N):
            # decreasing solvetime should increase weight
            base_weight = manager.generate_mining_block().weight
            add_new_blocks(manager, i, advance_clock=T)
            add_new_blocks(manager, 1, advance_clock=T * 0.9)
            add_new_blocks(manager, N - i, advance_clock=T)
            new_weight = manager.generate_mining_block().weight
            self.assertGreater(new_weight, base_weight)
            add_new_blocks(manager, N, advance_clock=T)
            # increasing solvetime should decrease weight
            base_weight = manager.generate_mining_block().weight
            add_new_blocks(manager, i, advance_clock=T)
            add_new_blocks(manager, 1, advance_clock=T * 1.1)
            add_new_blocks(manager, N - i, advance_clock=T)
            new_weight = manager.generate_mining_block().weight
            self.assertLess(new_weight, base_weight)

    def test_daa_weight_decay_amount(self):
        self.daa.TEST_MODE = TestMode.DISABLED
        amount = self._settings.WEIGHT_DECAY_AMOUNT

        for distance in range(0, self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE, 10):
            self.assertEqual(self.daa.get_weight_decay_amount(distance), 0)

        distance = self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE - 1
        self.assertAlmostEqual(self.daa.get_weight_decay_amount(distance), 0)

        distance = self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE
        for k in range(1, 11):
            for _ in range(self._settings.WEIGHT_DECAY_WINDOW_SIZE):
                self.assertAlmostEqual(self.daa.get_weight_decay_amount(distance), k * amount)
                distance += 1
        self.assertAlmostEqual(self.daa.get_weight_decay_amount(distance), 11 * amount)

    def test_daa_weight_decay_blocks(self):
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)
        manager.daa.TEST_MODE = TestMode.DISABLED
        amount = self._settings.WEIGHT_DECAY_AMOUNT

        manager.daa.AVG_TIME_BETWEEN_BLOCKS = self._settings.AVG_TIME_BETWEEN_BLOCKS
        manager.daa.MIN_BLOCK_WEIGHT = 2 + 2 * self._settings.WEIGHT_DECAY_AMOUNT
        add_new_blocks(
            manager,
            2 * self._settings.BLOCK_DIFFICULTY_N_BLOCKS,
            advance_clock=self._settings.AVG_TIME_BETWEEN_BLOCKS
        )

        manager.daa.MIN_BLOCK_WEIGHT = 1
        base_weight = manager.generate_mining_block().weight
        self.assertGreater(base_weight, manager.daa.MIN_BLOCK_WEIGHT)

        add_new_blocks(manager, 20, advance_clock=self._settings.AVG_TIME_BETWEEN_BLOCKS)

        dt = self._settings.AVG_TIME_BETWEEN_BLOCKS  # the latest call to add_new_blocks will advance the clock
        while dt < self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            weight = manager.generate_mining_block().weight
            self.assertAlmostEqual(weight, base_weight)
            manager.reactor.advance(1)
            dt += 1

        dt = 0
        while dt < self._settings.WEIGHT_DECAY_WINDOW_SIZE:
            weight = manager.generate_mining_block().weight
            self.assertAlmostEqual(weight, base_weight - amount)
            manager.reactor.advance(1)
            dt += 1

        dt = 0
        while dt < self._settings.WEIGHT_DECAY_WINDOW_SIZE:
            weight = manager.generate_mining_block().weight
            self.assertAlmostEqual(weight, base_weight - 2*amount)
            manager.reactor.advance(1)
            dt += 1

        manager.reactor.advance(1)
        weight = manager.generate_mining_block().weight
        self.assertAlmostEqual(weight, manager.daa.MIN_BLOCK_WEIGHT)
