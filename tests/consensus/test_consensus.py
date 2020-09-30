from hathor.conf import HathorSettings
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest
from tests.utils import (
    add_blocks_unlock_reward,
    add_new_block,
    add_new_blocks,
    add_new_double_spending,
    add_new_transactions,
)

settings = HathorSettings()


class ConsensusTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_revert_block_high_weight(self):
        """ A conflict transaction will be propagated. At first, it will be voided.
        But, a new block with high weight will verify it, which will flip it to executed.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager, use_same_parents=True)

        # Add a few transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})
        for parent_hash in conflicting_tx.parents:
            self.assertNotIn(parent_hash, meta.conflict_with)

        # These blocks will be voided later.
        blocks2 = add_new_blocks(manager, 2, advance_clock=15)

        # This block verifies the conflicting transaction and has a high weight.
        # So, it will be executed and previous blocks and transactions will be voided.
        tb0 = manager.make_custom_block_template(blocks[-1].hash, [conflicting_tx.hash, conflicting_tx.parents[0]])
        b0 = tb0.generate_mining_block(storage=manager.tx_storage)
        b0.weight = 10
        b0.resolve()
        b0.verify()
        manager.propagate_tx(b0, fails_silently=False)

        b1 = add_new_block(manager, advance_clock=15)
        b2 = add_new_block(manager, advance_clock=15)

        # from hathor.graphviz import GraphvizVisualizer
        # dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
        # dot.render('dot0')

        self.assertEqual(b1.parents[0], b0.hash)
        self.assertEqual(b2.parents[0], b1.hash)

        meta = conflicting_tx.get_metadata()
        self.assertIsNone(meta.voided_by)

        # Find the other transaction voiding the blocks.
        tmp_tx = manager.tx_storage.get_transaction(blocks2[0].parents[1])
        tmp_tx_meta = tmp_tx.get_metadata()
        self.assertEqual(len(tmp_tx_meta.voided_by), 1)
        other_tx_hash = list(tmp_tx_meta.voided_by)[0]

        for block in blocks2:
            meta = block.get_metadata()
            self.assertEqual(meta.voided_by, {other_tx_hash, block.hash})

        self.assertConsensusValid(manager)

    def test_dont_revert_block_low_weight(self):
        """ A conflict transaction will be propagated and voided.
        A new block with low weight will verify it, which won't be enough to flip to executed.
        So, it will remain voided.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager, use_same_parents=True)

        # Add a few transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})
        for parent_hash in conflicting_tx.parents:
            self.assertNotIn(parent_hash, meta.conflict_with)

        # These blocks will be voided later.
        add_new_blocks(manager, 2, advance_clock=15)

        # This block verifies the conflicting transaction and has a low weight.
        # So, it is not enough to revert and this block will be voided as well.
        b0 = manager.generate_mining_block()
        b0.parents = [blocks[-1].hash, conflicting_tx.hash, conflicting_tx.parents[0]]
        b0.resolve()
        b0.verify()
        manager.propagate_tx(b0, fails_silently=False)

        b1 = add_new_block(manager, advance_clock=15)
        b2 = add_new_block(manager, advance_clock=15)

        # dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
        # dot.render('dot1')

        self.assertNotEqual(b1.parents[0], b0.hash)
        self.assertEqual(b2.parents[0], b1.hash)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})

        b0_meta = b0.get_metadata()
        self.assertEqual(b0_meta.voided_by, {b0.hash, conflicting_tx.hash})

        self.assertConsensusValid(manager)

    def test_dont_revert_block_high_weight_transaction_verify_other(self):
        """ A conflict transaction will be propagated and voided. But this transaction
        verifies its conflicting transaction. So, its accumulated weight will always be smaller
        than the others and it will never be executed.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager)
        meta = conflicting_tx.get_metadata()
        self.assertEqual(len(meta.conflict_with), 1)
        self.assertIn(list(meta.conflict_with)[0], conflicting_tx.parents)

        # Add a few transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})

        # These blocks will be voided later.
        blocks2 = add_new_blocks(manager, 2, advance_clock=15)

        # This block verifies the conflicting transaction and has a high weight.
        tb0 = manager.make_custom_block_template(blocks[-1].hash, [conflicting_tx.hash, conflicting_tx.parents[0]])
        b0 = tb0.generate_mining_block(storage=manager.tx_storage)
        b0.weight = 10
        b0.resolve()
        b0.verify()
        manager.propagate_tx(b0, fails_silently=False)

        b1 = add_new_block(manager, advance_clock=15)
        b2 = add_new_block(manager, advance_clock=15)

        # dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
        # dot.render('dot2')

        self.assertNotEqual(b1.parents[0], b0.hash)
        self.assertEqual(b2.parents[0], b1.hash)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})

        for block in blocks2:
            meta = block.get_metadata()
            self.assertIsNone(meta.voided_by)

        self.assertConsensusValid(manager)

    def test_dont_revert_block_high_weight_verify_both(self):
        """ A conflicting transaction will be propagated and voided. But the block with high weight
        verifies both the conflicting transactions, so this block will always be voided.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager, use_same_parents=True)

        # Add a few transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})
        for parent_hash in conflicting_tx.parents:
            self.assertNotIn(parent_hash, meta.conflict_with)

        # Add two blocks.
        blocks2 = add_new_blocks(manager, 2, advance_clock=15)

        # This block verifies the conflicting transaction and has a high weight.
        b0 = manager.generate_mining_block()
        b0.parents = [b0.parents[0], conflicting_tx.hash, conflicting_tx.parents[0]]
        b0.weight = 10
        b0.resolve()
        b0.verify()
        manager.propagate_tx(b0, fails_silently=False)

        b1 = add_new_block(manager, advance_clock=15)
        b2 = add_new_block(manager, advance_clock=15)

        # dot = GraphvizVisualizer(manager.tx_storage, include_verifications=True, include_funds=True).dot()
        # dot.render('dot3')

        self.assertNotEqual(b1.parents[0], b0.hash)
        self.assertEqual(b2.parents[0], b1.hash)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})

        for block in blocks2:
            meta = block.get_metadata()
            self.assertIsNone(meta.voided_by)

        self.assertConsensusValid(manager)
