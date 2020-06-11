import random

from hathor.crypto.util import decode_address
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, add_new_tx, start_remote_storage


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)

        self.genesis = self.manager1.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def _add_new_transactions(self, manager, num_txs):
        txs = []
        for _ in range(num_txs):
            address = self.get_address(0)
            value = random.choice([5, 10, 15, 20])
            tx = add_new_tx(manager, address, value)
            txs.append(tx)
        return txs

    def test_simple_double_spending(self):
        add_new_blocks(self.manager1, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager1)

        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletOutputInfo

        address = self.get_address(0)
        value = 500

        outputs = []
        outputs.append(
            WalletOutputInfo(address=decode_address(address), value=value, timelock=None))

        tx1 = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx1.weight = 10
        tx1.parents = self.manager1.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()

        tx2 = Transaction.create_from_struct(tx1.get_struct())
        tx2.weight = 10
        tx2.parents = tx2.parents[::-1]
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        self.assertNotEqual(tx1.hash, tx2.hash)

        tx3 = Transaction.create_from_struct(tx1.get_struct())
        tx3.weight = 11
        tx3.timestamp = int(self.clock.seconds())
        tx3.resolve()
        self.assertNotEqual(tx1.hash, tx3.hash)
        self.assertNotEqual(tx2.hash, tx3.hash)

        self.assertTrue(self.manager1.propagate_tx(tx1, False))
        self.run_to_completion()
        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.conflict_with, None)
        self.assertEqual(meta1.voided_by, None)

        # Propagate a conflicting transaction.
        self.assertTrue(self.manager1.propagate_tx(tx2, False))
        self.run_to_completion()

        meta1 = tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx2.hash])
        self.assertEqual(meta1.voided_by, {tx1.hash})

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.conflict_with, [tx1.hash])
        self.assertEqual(meta2.voided_by, {tx2.hash})

        for txin in tx1.inputs:
            spent_tx = self.manager1.tx_storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            self.assertEqual([tx1.hash, tx2.hash], spent_meta.spent_outputs[txin.index])

        self.assertNotIn(tx1.hash, [x.data for x in self.manager1.tx_storage.get_tx_tips()])
        self.assertNotIn(tx2.hash, [x.data for x in self.manager1.tx_storage.get_tx_tips()])

        # Propagate another conflicting transaction, but with higher weight.
        self.manager1.propagate_tx(tx3)
        self.run_to_completion()

        meta1 = tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx2.hash, tx3.hash])
        self.assertEqual(meta1.voided_by, {tx1.hash})

        meta2 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta2.conflict_with, [tx1.hash, tx3.hash])
        self.assertEqual(meta2.voided_by, {tx2.hash})

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.conflict_with, [tx1.hash, tx2.hash])
        self.assertEqual(meta3.voided_by, None)

        for txin in tx1.inputs:
            spent_tx = self.manager1.tx_storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            self.assertEqual([tx1.hash, tx2.hash, tx3.hash], spent_meta.spent_outputs[txin.index])

        self.assertNotIn(tx1.hash, [x.data for x in self.manager1.tx_storage.get_tx_tips()])
        self.assertNotIn(tx2.hash, [x.data for x in self.manager1.tx_storage.get_tx_tips()])
        self.assertIn(tx3.hash, [x.data for x in self.manager1.tx_storage.get_tx_tips()])

        self.assertConsensusValid(self.manager1)

    def test_double_spending_propagation(self):
        blocks = add_new_blocks(self.manager1, 4, advance_clock=15)
        add_blocks_unlock_reward(self.manager1)

        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo

        # ---
        # tx1 and tx4 spends the same output (double spending)
        # tx2 spends one tx1's input
        # tx3 verifies tx1, but does not spend any of tx1's inputs
        # tx5 spends one tx4's input
        # tx6 is a twin of tx3, but verifying tx4 and tx5
        # tx7 verifies tx4, but does not spend any of tx4's inputs
        # ---
        # tx1.weight = 5
        # tx2.weight = 5
        # tx3.weight = 5
        # tx4.weight = 5
        # tx5.weight = 5
        # tx6.weight = 1
        # tx7.weight = 10
        # ---

        address = self.manager1.wallet.get_unused_address_bytes()
        value = 100
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        self.clock.advance(1)
        tx1 = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx1.weight = 5
        tx1.parents = self.manager1.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()

        address = self.manager1.wallet.get_unused_address_bytes()
        value = 500
        tx_total_value = sum(txout.value for txout in tx1.outputs)
        outputs = [WalletOutputInfo(address=address, value=value, timelock=None),
                   WalletOutputInfo(address=address, value=tx_total_value - 500, timelock=None)]
        self.clock.advance(1)
        inputs = [WalletInputInfo(i.tx_id, i.index, b'') for i in tx1.inputs]
        tx4 = self.manager1.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs,
                                                                         outputs, self.manager1.tx_storage)
        tx4.weight = 5
        tx4.parents = self.manager1.get_new_tx_parents()
        tx4.timestamp = int(self.clock.seconds())
        tx4.resolve()

        self.assertEqual(tx1.inputs[0].tx_id, tx4.inputs[0].tx_id)
        self.assertEqual(tx1.inputs[0].index, tx4.inputs[0].index)

        # ---

        self.clock.advance(15)
        self.assertTrue(self.manager1.propagate_tx(tx1))
        print('tx1', tx1.hash.hex())
        self.clock.advance(15)

        # ---

        address = self.manager1.wallet.get_unused_address_bytes()
        value = 100
        inputs = [WalletInputInfo(tx_id=tx1.hash, index=1, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        self.clock.advance(1)
        tx2 = self.manager1.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                         self.manager1.tx_storage)
        tx2.weight = 5
        tx2.parents = tx1.parents
        tx2.timestamp = int(self.clock.seconds())
        tx2.resolve()
        self.clock.advance(15)
        self.manager1.propagate_tx(tx2)
        print('tx2', tx2.hash.hex())
        self.clock.advance(15)

        self.assertGreater(tx2.timestamp, tx1.timestamp)

        # ---

        address = self.manager1.wallet.get_unused_address_bytes()
        value = 500
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        self.clock.advance(1)
        tx3 = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        self.assertNotEqual(tx3.inputs[0].tx_id, tx1.hash)
        self.assertNotEqual(tx3.inputs[0].tx_id, tx2.hash)
        tx3.weight = 5
        tx3.parents = [tx1.hash, tx1.parents[0]]
        tx3.timestamp = int(self.clock.seconds())
        tx3.resolve()
        self.clock.advance(15)
        self.assertTrue(self.manager1.propagate_tx(tx3))
        print('tx3', tx3.hash.hex())
        self.clock.advance(15)

        # ---

        self.clock.advance(15)
        self.assertTrue(self.manager1.propagate_tx(tx4, False))
        print('tx4', tx4.hash.hex())
        self.clock.advance(15)

        self.run_to_completion()
        meta1 = tx1.get_metadata(force_reload=True)
        meta4 = tx4.get_metadata(force_reload=True)
        self.assertEqual(meta1.conflict_with, [tx4.hash])
        self.assertEqual(meta1.voided_by, None)
        self.assertEqual(meta4.conflict_with, [tx1.hash])
        self.assertEqual(meta4.voided_by, {tx4.hash})

        # ---

        address = self.manager1.wallet.get_unused_address_bytes()
        value = 500
        inputs = [WalletInputInfo(tx_id=tx4.hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=int(value), timelock=None)]
        self.clock.advance(1)
        tx5 = self.manager1.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs, force=True,
                                                                         tx_storage=self.manager1.tx_storage)
        tx5.weight = 5
        tx5.parents = tx1.parents
        tx5.timestamp = int(self.clock.seconds())
        tx5.resolve()
        self.clock.advance(15)
        self.manager1.propagate_tx(tx5)
        print('tx5', tx5.hash.hex())
        self.clock.advance(15)

        meta5 = tx5.get_metadata()
        self.assertEqual(meta5.conflict_with, None)
        self.assertEqual(meta5.voided_by, {tx4.hash})

        # ---

        self.clock.advance(1)
        tx6 = Transaction.create_from_struct(tx3.get_struct())
        tx6.weight = 1
        tx6.parents = [tx4.hash, tx5.hash]
        tx6.timestamp = int(self.clock.seconds())
        tx6.resolve()
        self.clock.advance(15)
        self.manager1.propagate_tx(tx6)
        print('tx6', tx6.hash.hex())
        self.clock.advance(15)

        meta6 = tx6.get_metadata()
        self.assertEqual(meta6.conflict_with, [tx3.hash])
        self.assertEqual(meta6.voided_by, {tx4.hash, tx6.hash})

        # ---

        address = self.manager1.wallet.get_unused_address_bytes()
        value = blocks[3].outputs[0].value
        inputs = [WalletInputInfo(tx_id=blocks[3].hash, index=0, private_key=None)]
        outputs = [WalletOutputInfo(address=address, value=value, timelock=None)]
        self.clock.advance(1)
        tx7 = self.manager1.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                         self.manager1.tx_storage)
        tx7.weight = 10
        tx7.parents = [tx4.hash, tx5.hash]
        tx7.timestamp = int(self.clock.seconds())
        tx7.resolve()
        self.clock.advance(15)
        self.manager1.propagate_tx(tx7, False)
        print('tx7', tx7.hash.hex())
        self.clock.advance(15)

        meta1 = tx1.get_metadata(force_reload=True)
        meta2 = tx2.get_metadata(force_reload=True)
        meta3 = tx3.get_metadata(force_reload=True)
        self.assertEqual(meta1.voided_by, {tx1.hash})
        self.assertEqual(meta2.voided_by, {tx1.hash})
        self.assertEqual(meta3.voided_by, {tx1.hash, tx3.hash})

        meta4 = tx4.get_metadata(force_reload=True)
        meta5 = tx5.get_metadata(force_reload=True)
        meta6 = tx6.get_metadata(force_reload=True)
        meta7 = tx7.get_metadata(force_reload=True)
        self.assertEqual(meta4.voided_by, None)
        self.assertEqual(meta5.voided_by, None)
        self.assertEqual(meta6.voided_by, None)
        self.assertEqual(meta7.voided_by, None)

        blocks = add_new_blocks(self.manager1, 1, advance_clock=15)
        add_blocks_unlock_reward(self.manager1)
        self._add_new_transactions(self.manager1, 10)
        blocks = add_new_blocks(self.manager1, 1, advance_clock=15)
        add_blocks_unlock_reward(self.manager1)
        self._add_new_transactions(self.manager1, 10)
        blocks = add_new_blocks(self.manager1, 1, advance_clock=15)

        self.assertConsensusValid(self.manager1)

        # ---
        # dot1 = self.manager1.tx_storage.graphviz(format='pdf', acc_weight=True)
        # dot1.render('dot1')

        # dot2 = self.manager1.tx_storage.graphviz_funds(format='pdf', acc_weight=True)
        # dot2.render('dot2')


class RemoteStorageSyncTest(HathorSyncMethodsTestCase):
    def setUp(self):
        super().setUp()
        tx_storage, self._server = start_remote_storage()

        self.manager1.tx_storage = tx_storage

    def tearDown(self):
        self._server.stop(0).wait()
        super().tearDown()
