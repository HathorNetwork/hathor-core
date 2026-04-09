from hathor.simulator.utils import add_new_blocks
from hathor.utils.weight import weight_to_work
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_transactions


class AccumulatedWeightTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tx_storage = self.create_tx_storage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_accumulated_weight_indirect_block(self):
        """ All new blocks belong to case (i).
        """
        self.assertEqual(len(self.genesis_blocks), 1)
        manager = self.create_peer('testnet', tx_storage=self.tx_storage)

        # Mine 3 blocks in a row with no transaction but the genesis
        blocks = add_new_blocks(manager, 3, advance_clock=15)
        add_blocks_unlock_reward(manager)

        # Add some transactions between blocks
        tx_list = add_new_transactions(manager, 20, advance_clock=15)

        # Mine more 2 blocks in a row with no transactions between them
        blocks = add_new_blocks(manager, 2, weight=8)

        tx0 = tx_list[0]
        for block in blocks:
            self.assertNotIn(tx0.hash, block.parents)

        # All transactions and blocks should be verifying tx_list[0] directly or
        # indirectly.
        expected = 0
        for tx in tx_list:
            expected += weight_to_work(tx.weight)
        for block in blocks:
            expected += weight_to_work(block.weight)

        meta = tx0.update_accumulated_weight()
        self.assertAlmostEqual(meta.accumulated_weight, expected)
