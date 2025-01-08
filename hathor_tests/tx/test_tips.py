from itertools import chain

from hathor.simulator.utils import add_new_block, add_new_blocks
from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_double_spending, add_new_transactions


class TipsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

    def get_tips(self):
        assert self.manager.tx_storage.indexes is not None
        assert self.manager.tx_storage.indexes.mempool_tips is not None
        return self.manager.tx_storage.indexes.mempool_tips.get()

    def test_tips_back(self):
        add_new_block(self.manager, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.get_tips()), 0)

        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx will be the tip
        self.assertCountEqual(self.get_tips(), set([tx.hash]))

        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx2 will be the tip now
        self.assertCountEqual(self.get_tips(), set([tx2.hash]))

        # with a double spending tx2 must continue being the tip
        add_new_double_spending(self.manager)
        self.assertCountEqual(self.get_tips(), set([tx2.hash]))

    def test_tips_winner(self):
        add_new_block(self.manager, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.get_tips()), 0)

        tx1 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx1 will be the tip
        self.assertCountEqual(self.get_tips(), set([tx1.hash]))

        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx2 will be the tip now
        self.assertCountEqual(self.get_tips(), set([tx2.hash]))

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.parents = [tx2.parents[1], tx2.parents[0]]
        self.manager.cpu_mining_service.resolve(tx3)

        # Propagate a conflicting twin transaction with tx2
        self.manager.propagate_tx(tx3)

        meta1 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx3.hash])
        self.assertEqual(meta1.voided_by, {tx2.hash})
        self.assertEqual(meta1.twins, [tx3.hash])
        self.assertCountEqual(self.get_tips(), set([tx1.hash]))

        self.manager.reactor.advance(10)

        # Creating a new block that confirms tx3, then is will become valid and voiding tx2
        new_block = add_new_block(self.manager, propagate=False)
        new_block.parents = [new_block.parents[0], tx1.hash, tx3.hash]
        self.manager.cpu_mining_service.resolve(new_block)
        self.manager.propagate_tx(new_block)

        self.manager.reactor.advance(10)

        self.assertIsNone(self.manager.tx_storage.get_metadata(tx3.hash).voided_by)
        self.assertIsNotNone(self.manager.tx_storage.get_metadata(tx2.hash).voided_by)
        # The block confirms tx3, so it's not a tip
        self.assertCountEqual(self.get_tips(), set())

    def test_choose_tips(self):
        genesis = self.manager.tx_storage.get_all_genesis()
        genesis_txs_hashes = [tx.hash for tx in genesis if not tx.is_block]

        b = add_new_block(self.manager, advance_clock=1)
        # The txs parents are the genesis
        self.assertCountEqual(set(b.parents[1:]), set(genesis_txs_hashes))
        reward_blocks = add_blocks_unlock_reward(self.manager)
        # No tips
        self.assertEqual(len(self.get_tips()), 0)

        tx1, = add_new_transactions(self.manager, 1, advance_clock=1, name='tx1')
        # The tx parents will be the genesis txs still
        self.assertCountEqual(set(tx1.parents), set(genesis_txs_hashes))
        # The new tx will be a tip
        self.assertCountEqual(self.get_tips(), set([tx1.hash]))

        tx2, = add_new_transactions(self.manager, 1, advance_clock=1, name='tx2')
        # The tx2 parents will be the tx1 and one of the genesis
        self.assertTrue(tx1.hash in tx2.parents)
        # The other parent will be one of tx1 parents
        self.assertTrue(set(tx2.parents).issubset(set([tx1.hash] + tx1.parents)))
        self.assertCountEqual(self.get_tips(), set([tx2.hash]))

        tx3, = add_new_transactions(self.manager, 1, advance_clock=1, name='tx3')
        self.manager.tx_storage.get_best_block()
        # tx3 parents will be tx2 and tx1
        self.assertEqual(tx3.parents, [tx2.hash, tx1.hash])
        self.assertCountEqual(self.get_tips(), set([tx3.hash]))

        b2 = add_new_block(self.manager, advance_clock=1)
        # With new block there are no tips and block parents
        # will be tx3 and one of tx3 parents
        self.assertEqual(len(self.get_tips()), 0)
        self.assertTrue(tx3.hash in b2.parents)
        self.assertTrue(reward_blocks[-1].hash in b2.parents)
        self.log.debug('b2 parents', p1=b2.parents[0].hex(), p2=b2.parents[1].hex())
        possible_parents = set(chain([tx3.hash], tx3.parents, b2.parents))
        self.log.debug('possible parents', p=[i.hex() for i in possible_parents])
        self.assertTrue(set(b2.parents).issubset(possible_parents))

        tx4 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # tx4 had no tip, so the parents will be tx3 and one of tx3 parents
        self.assertTrue(tx3.hash in tx4.parents)
        self.assertTrue(set(tx4.parents).issubset(set([tx3.hash] + tx3.parents)))
        # Then tx4 will become a tip
        self.assertCountEqual(self.get_tips(), set([tx4.hash]))

    def test_tips_twin(self):
        add_new_blocks(self.manager, 6, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(len(self.get_tips()), 0)

        tx1 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        tx2 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        tx3 = add_new_transactions(self.manager, 1, advance_clock=1)[0]
        # 3 txs and the last one is still a tip
        self.assertCountEqual(self.get_tips(), set([tx3.hash]))

        # A new tx with custom parents, so tx3 and tx4 will become two tips
        tx4 = add_new_transactions(self.manager, 1, advance_clock=1, propagate=False)[0]
        tx4.parents = [tx1.hash, tx2.hash]
        self.manager.cpu_mining_service.resolve(tx4)
        self.manager.propagate_tx(tx4)
        self.manager.reactor.advance(10)
        self.assertCountEqual(self.get_tips(), set([tx4.hash, tx3.hash]))

        # A twin tx with tx4, that will be voided initially, then won't change the tips
        tx5 = Transaction.create_from_struct(tx4.get_struct())
        tx5.parents = [tx2.hash, tx3.hash]
        self.manager.cpu_mining_service.resolve(tx5)
        self.manager.propagate_tx(tx5)
        self.manager.reactor.advance(10)

        # tx4 and tx5 are twins, so both are voided
        self.assertIsNotNone(tx4.get_metadata(force_reload=True).voided_by)
        self.assertIsNotNone(tx5.get_metadata(force_reload=True).voided_by)
        self.assertCountEqual(self.get_tips(), set([tx3.hash]))

        # add new tx confirming tx5, which will become valid and tx4 becomes voided
        tx6 = add_new_transactions(self.manager, 1, advance_clock=1, propagate=False)[0]
        tx6.parents = [tx5.hash, tx2.hash]
        self.manager.cpu_mining_service.resolve(tx6)
        self.manager.propagate_tx(tx6)
        self.manager.reactor.advance(10)
        self.assertIsNotNone(tx4.get_metadata(force_reload=True).voided_by)
        self.assertIsNone(tx5.get_metadata(force_reload=True).voided_by)

        # tx6 is the only one left
        self.assertCountEqual(self.get_tips(), set([tx6.hash]))
