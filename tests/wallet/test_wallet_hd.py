from hathor.transaction import Transaction
from hathor.wallet import HDWallet
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet.exceptions import InsuficientFunds

from tests import unittest

TOKENS = 100


class WalletHD(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = HDWallet()
        self.wallet._manually_initialize()
        self.memory_storage = TransactionMemoryStorage()
        self.wallet.unlock(tx_storage=self.memory_storage)

    def test_transaction_and_balance(self):
        # generate a new block and check if we increase balance
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address), TOKENS)
        tx = self.wallet.prepare_transaction(Transaction, inputs=[], outputs=[out])
        tx.update_hash()
        self.wallet.on_new_tx(tx)
        self.assertEqual(len(self.wallet.unspent_txs[new_address]), 1)
        self.assertEqual(self.wallet.balance, TOKENS)

        # create transaction spending this value, but sending to same wallet
        new_address2 = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address2), TOKENS)
        tx1 = self.wallet.prepare_transaction_compute_inputs(Transaction, outputs=[out])
        tx1.update_hash()
        self.wallet.on_new_tx(tx1)
        self.assertEqual(len(self.wallet.spent_txs), 1)
        self.assertEqual(len(self.wallet.unspent_txs), 1)
        self.assertEqual(self.wallet.balance, TOKENS)

        # pass inputs and outputs to prepare_transaction, but not the input keys
        # spend output last transaction
        input_info = WalletInputInfo(tx1.hash, 0, None)
        new_address3 = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address3), TOKENS)
        tx2 = self.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs=[input_info], outputs=[out])
        tx2.update_hash()
        self.wallet.on_new_tx(tx2)
        self.assertEqual(len(self.wallet.spent_txs), 2)
        self.assertEqual(self.wallet.balance, TOKENS)

    def test_insuficient_funds(self):
        # create transaction spending some value
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address), TOKENS)
        with self.assertRaises(InsuficientFunds):
            self.wallet.prepare_transaction_compute_inputs(Transaction, outputs=[out])

    def test_lock(self):
        # Test locking and unlocking wallet

        # Initially is unlocked
        self.assertFalse(self.wallet.is_locked())
        words = self.wallet.words
        address = self.wallet.get_unused_address()

        # We lock
        self.wallet.lock()

        # Now it's locked
        self.assertTrue(self.wallet.is_locked())

        # We unlock
        self.wallet.unlock(tx_storage=self.memory_storage, words=words)

        self.assertFalse(self.wallet.is_locked())
        self.assertEqual(address, self.wallet.get_unused_address())
