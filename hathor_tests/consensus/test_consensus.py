from unittest.mock import MagicMock, Mock

from hathor.execution_manager import ExecutionManager
from hathor.simulator.utils import add_new_block, add_new_blocks, gen_new_tx
from hathor.util import not_none
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_double_spending, add_new_transactions


class ConsensusTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.tx_storage = self.create_tx_storage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_unhandled_exception(self) -> None:
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        address = 'HGov979VaeyMQ92ubYcnVooP6qPzUJU8Ro'
        value = 1
        tx = gen_new_tx(manager, address, value)

        class MyError(Exception):
            pass

        execution_manager_mock = Mock(spec_set=ExecutionManager)
        manager.vertex_handler._execution_manager = execution_manager_mock
        manager.consensus_algorithm.unsafe_update = MagicMock(side_effect=MyError)

        manager.propagate_tx(tx)

        execution_manager_mock.crash_and_exit.assert_called_once_with(
            reason=f"on_new_vertex() failed for tx {tx.hash_hex}"
        )

        tx2 = manager.tx_storage.get_transaction(tx.hash)
        meta2 = tx2.get_metadata()
        self.assertEqual({self._settings.CONSENSUS_FAIL_ID}, meta2.voided_by)

    def test_revert_block_high_weight(self) -> None:
        """ A conflict transaction will be propagated. At first, it will be voided.
        But, a new block with high weight will verify it, which will flip it to executed.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        add_new_blocks(manager, 3, advance_clock=15)
        blocks = add_blocks_unlock_reward(manager)

        # Add some transactions after blocks
        add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager, use_same_parents=True)

        # Add a few more transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})
        for parent_hash in conflicting_tx.parents:
            self.assertNotIn(parent_hash, meta.conflict_with)

        # These blocks will be voided later.
        blocks2 = add_new_blocks(manager, 2, advance_clock=15)
        self.assertEqual(blocks[-1].hash, blocks2[0].parents[0])

        # This block verifies the conflicting transaction and has a high weight.
        # So, it will be executed and previous blocks and transactions will be voided.
        tb0 = manager.make_custom_block_template(blocks[-1].hash, [conflicting_tx.hash, conflicting_tx.parents[0]])
        b0 = tb0.generate_mining_block(manager.rng, storage=manager.tx_storage)
        b0.weight = 10
        manager.cpu_mining_service.resolve(b0)
        manager.propagate_tx(b0)

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

    def test_dont_revert_block_low_weight(self) -> None:
        """ A conflict transaction will be propagated and voided.
        A new block with low weight will verify it, which won't be enough to flip to executed.
        So, it will remain voided.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        add_new_blocks(manager, 3, advance_clock=15)
        blocks = add_blocks_unlock_reward(manager)

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
        manager.cpu_mining_service.resolve(b0)
        manager.propagate_tx(b0)

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

    def test_dont_revert_block_high_weight_transaction_verify_other(self) -> None:
        """ A conflict transaction will be propagated and voided. But this transaction
        verifies its conflicting transaction. So, its accumulated weight will always be smaller
        than the others and it will never be executed.
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine a few blocks in a row with no transaction but the genesis
        add_new_blocks(manager, 3, advance_clock=15)
        blocks = add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        txs = add_new_transactions(manager, 5, advance_clock=15)

        # Create a double spending transaction.
        conflicting_tx = add_new_double_spending(manager, tx=txs[-1])
        meta = conflicting_tx.get_metadata()
        self.assertEqual(len(not_none(meta.conflict_with)), 1)
        self.assertIn(not_none(meta.conflict_with)[0], conflicting_tx.parents)

        # Add a few transactions.
        add_new_transactions(manager, 10, advance_clock=15)

        meta = conflicting_tx.get_metadata()
        self.assertEqual(meta.voided_by, {conflicting_tx.hash})

        # These blocks will be voided later.
        blocks2 = add_new_blocks(manager, 2, advance_clock=15)
        self.assertEqual(blocks[-1].hash, blocks2[0].parents[0])

        # This block verifies the conflicting transaction and has a high weight.
        tb0 = manager.make_custom_block_template(blocks[-1].hash, [conflicting_tx.hash, conflicting_tx.parents[0]])
        b0 = tb0.generate_mining_block(manager.rng, storage=manager.tx_storage)
        b0.weight = 10
        manager.cpu_mining_service.resolve(b0)
        manager.propagate_tx(b0)

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

    def test_dont_revert_block_high_weight_verify_both(self) -> None:
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
        manager.cpu_mining_service.resolve(b0)
        manager.propagate_tx(b0)

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
