from hathor.transaction import Transaction
from tests import unittest
from tests.utils import (
    add_blocks_unlock_reward,
    add_new_block,
    add_new_blocks,
    add_new_double_spending,
    add_new_transactions,
)


class BaseTipsTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

    def test_tips_back(self):
        add_new_block(self.manager, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.manager.tx_storage._tx_tips_index), 0)

        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx will be the tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx.hash]))

        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx2 will be the tip now
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx2.hash]))

        # with a double spending tx2 must continue being the tip
        add_new_double_spending(self.manager)
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx2.hash]))

    def test_tips_winner(self):
        # b = add_new_block(self.manager, advance_clock=1)
        # reward_blocks = add_blocks_unlock_reward(self.manager)
        add_new_block(self.manager, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.manager.tx_storage._tx_tips_index), 0)

        tx1 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx1 will be the tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx1.hash]))

        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx2 will be the tip now
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx2.hash]))

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.parents = [tx2.parents[1], tx2.parents[0]]
        tx3.resolve()

        # Propagate a conflicting twin transaction with tx2
        self.manager.propagate_tx(tx3)

        meta1 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx3.hash])
        self.assertEqual(meta1.voided_by, {tx2.hash})
        self.assertEqual(meta1.twins, [tx3.hash])
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx1.hash]))

        self.manager.reactor.advance(10)

        # Creating a new block that confirms tx3, then is will become valid and voiding tx2
        new_block = add_new_block(self.manager, propagate=False)
        new_block.parents = [new_block.parents[0], tx1.hash, tx3.hash]
        new_block.resolve()
        new_block.verify()
        self.manager.propagate_tx(new_block, fails_silently=False)

        self.manager.reactor.advance(10)

        self.assertIsNone(self.manager.tx_storage.get_metadata(tx3.hash).voided_by)
        self.assertIsNotNone(self.manager.tx_storage.get_metadata(tx2.hash).voided_by)
        # The block confirms tx3, so it's not a tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set())

    def test_choose_tips(self):
        genesis = self.manager.tx_storage.get_all_genesis()
        genesis_txs_hashes = [tx.hash for tx in genesis if not tx.is_block]

        b = add_new_block(self.manager, advance_clock=1)
        # The txs parents are the genesis
        self.assertCountEqual(set(b.parents[1:]), set(genesis_txs_hashes))
        reward_blocks = add_blocks_unlock_reward(self.manager)
        # No tips
        self.assertEqual(len(self.manager.tx_storage._tx_tips_index), 0)

        tx1 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # The tx parents will be the genesis txs still
        self.assertCountEqual(set(tx1.parents), set(genesis_txs_hashes))
        # The new tx will be a tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx1.hash]))

        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # The tx2 parents will be the tx1 and one of the genesis
        self.assertTrue(tx1.hash in tx2.parents)
        # The other parent will be one of tx1 parents
        self.assertTrue(set(tx2.parents).issubset(set([tx1.hash] + tx1.parents)))
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx2.hash]))

        tx3 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx3 parents will be tx2 and one of tx2 parents
        self.assertTrue(tx2.hash in tx3.parents)
        self.assertTrue(set(tx3.parents).issubset(set([tx2.hash] + tx2.parents)))
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx3.hash]))

        b2 = add_new_block(self.manager, advance_clock=1)
        # With new block there are no tips and block parents
        # will be tx3 and one of tx3 parents
        self.assertEqual(len(self.manager.tx_storage._tx_tips_index), 0)
        self.assertTrue(tx3.hash in b2.parents)
        self.assertTrue(reward_blocks[-1].hash in b2.parents)
        self.assertTrue(set(b2.parents).issubset(set([tx3.hash] + [reward_blocks[-1].hash] + tx3.parents)))

        tx4 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx4 had no tip, so the parents will be the last block parents
        self.assertCountEqual(set(tx4.parents), set(b2.parents[1:]))
        # Then tx4 will become a tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx4.hash]))

    def test_tips_twin(self):
        # b = add_new_blocks(self.manager, 6, advance_clock=1)
        # reward_blocks = add_blocks_unlock_reward(self.manager)
        add_new_blocks(self.manager, 6, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.manager.tx_storage._tx_tips_index), 0)

        tx1 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        tx3 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # 3 txs and the last one is still a tip
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx3.hash]))

        # A new tx with custom parents, so tx3 and tx4 will become two tips
        tx4 = add_new_transactions(self.manager, 1, advance_clock=1, propagate=False)[0]
        tx4.parents = [tx1.hash, tx2.hash]
        tx4.resolve()
        self.manager.propagate_tx(tx4, fails_silently=False)
        self.manager.reactor.advance(10)
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx4.hash, tx3.hash]))

        # A twin tx with tx4, that will be voided initially, then won't change the tips
        tx5 = Transaction.create_from_struct(tx4.get_struct())
        tx5.parents = [tx2.hash, tx3.hash]
        tx5.resolve()
        self.manager.propagate_tx(tx5)
        self.manager.reactor.advance(10)

        # tx4 and tx5 are twins, so both are voided
        self.assertIsNotNone(tx4.get_metadata(force_reload=True).voided_by)
        self.assertIsNotNone(tx5.get_metadata(force_reload=True).voided_by)
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx3.hash]))

        # add new tx confirming tx5, which will become valid and tx4 becomes voided
        tx6 = add_new_transactions(self.manager, 1, advance_clock=1, propagate=False)[0]
        tx6.parents = [tx5.hash, tx2.hash]
        tx6.resolve()
        self.manager.propagate_tx(tx6, fails_silently=False)
        self.manager.reactor.advance(10)
        self.assertIsNotNone(tx4.get_metadata(force_reload=True).voided_by)
        self.assertIsNone(tx5.get_metadata(force_reload=True).voided_by)

        # tx6 is the only one left
        self.assertCountEqual(self.manager.tx_storage._tx_tips_index, set([tx6.hash]))


class SyncV1TipsTestCase(unittest.SyncV1Params, BaseTipsTestCase):
    __test__ = True


class SyncV2TipsTestCase(unittest.SyncV2Params, BaseTipsTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeTipsTestCase(unittest.SyncBridgeParams, SyncV2TipsTestCase):
    pass
