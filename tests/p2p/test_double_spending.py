from twisted.python import log
from twisted.internet.task import Clock

from hathor.transaction import TxConflictState

from tests import unittest

import sys
import base58


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        log.startLogging(sys.stdout)
        self.clock = Clock()
        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)

        self.genesis = self.manager1.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def _add_new_block(self):
        block = self.manager1.generate_mining_block()
        self.assertTrue(block.resolve())
        self.manager1.propagate_tx(block)
        return block

    def _add_new_blocks(self, num_blocks):
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block())
        return blocks

    def test_simple_double_spending(self):
        self._add_new_blocks(5)

        from hathor.transaction import Transaction
        from hathor.wallet.wallet import WalletOutputInfo

        address = '3JEcJKVsHddj1Td2KDjowZ1JqGF1'
        value = 1000

        outputs = []
        outputs.append(WalletOutputInfo(address=base58.b58decode(address), value=int(value)))

        tx1 = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx1.weight = 10
        tx1.parents = self.manager1.get_new_tx_parents()
        tx1.resolve()

        tx2 = Transaction.create_from_struct(tx1.get_struct())
        tx2.weight = 10
        tx2.parents = tx2.parents[::-1]
        tx2.resolve()
        self.assertNotEqual(tx1.hash, tx2.hash)

        tx3 = Transaction.create_from_struct(tx1.get_struct())
        tx3.weight = 11
        tx3.resolve()
        self.assertNotEqual(tx1.hash, tx3.hash)
        self.assertNotEqual(tx2.hash, tx3.hash)

        self.manager1.propagate_tx(tx1)
        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.conflict, TxConflictState.NO_CONFLICT)

        # Propagate a conflicting transaction.
        self.manager1.propagate_tx(tx2)

        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.conflict, TxConflictState.CONFLICT_VOIDED)

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.conflict, TxConflictState.CONFLICT_VOIDED)

        for txin in tx1.inputs:
            spent_tx = self.manager1.tx_storage.get_transaction_by_hash_bytes(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            self.assertEqual({tx1.hash, tx2.hash}, spent_meta.spent_outputs[txin.index])

        self.assertNotIn(tx1.hash, self.manager1.tx_storage.get_tip_transactions_hashes())
        self.assertNotIn(tx2.hash, self.manager1.tx_storage.get_tip_transactions_hashes())

        # Propagate another conflicting transaction, but with higher weight.
        self.manager1.propagate_tx(tx3)

        meta1 = tx1.get_metadata()
        self.assertEqual(meta1.conflict, TxConflictState.CONFLICT_VOIDED)

        meta2 = tx2.get_metadata()
        self.assertEqual(meta2.conflict, TxConflictState.CONFLICT_VOIDED)

        meta3 = tx3.get_metadata()
        self.assertEqual(meta3.conflict, TxConflictState.CONFLICT_WINNER)

        for txin in tx1.inputs:
            spent_tx = self.manager1.tx_storage.get_transaction_by_hash_bytes(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            self.assertEqual({tx1.hash, tx2.hash, tx3.hash}, spent_meta.spent_outputs[txin.index])

        self.assertNotIn(tx1.hash, self.manager1.tx_storage.get_tip_transactions_hashes())
        self.assertNotIn(tx2.hash, self.manager1.tx_storage.get_tip_transactions_hashes())
        self.assertIn(tx3.hash, self.manager1.tx_storage.get_tip_transactions_hashes())
