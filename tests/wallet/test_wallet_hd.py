from hathor.transaction import Transaction
from hathor.wallet import HDWallet
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo, WalletBalance
from hathor.wallet.exceptions import InsuficientFunds
from hathor.constants import TOKENS_PER_BLOCK, DECIMAL_PLACES

from tests import unittest
from tests.utils import add_new_block

BLOCK_TOKENS = TOKENS_PER_BLOCK * (10 ** DECIMAL_PLACES)
TOKENS = BLOCK_TOKENS


class WalletHD(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = HDWallet(gap_limit=2)
        self.wallet._manually_initialize()
        self.manager = self.create_peer('testnet', wallet=self.wallet, unlock_wallet=False)
        self.tx_storage = self.manager.tx_storage
        self.wallet.unlock(tx_storage=self.tx_storage)

    def test_transaction_and_balance(self):
        # generate a new block and check if we increase balance
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address), TOKENS, timelock=None)
        block = add_new_block(self.manager)
        block.verify()
        self.assertEqual(len(self.wallet.unspent_txs[new_address]), 1)
        self.assertEqual(self.wallet.balance, WalletBalance(0, BLOCK_TOKENS))

        # create transaction spending this value, but sending to same wallet
        new_address2 = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address2), TOKENS, timelock=None)
        tx1 = self.wallet.prepare_transaction_compute_inputs(Transaction, outputs=[out])
        tx1.update_hash()
        tx1.verify_script(tx1.inputs[0], block)
        self.wallet.on_new_tx(tx1)
        self.assertEqual(len(self.wallet.spent_txs), 1)
        self.assertEqual(len(self.wallet.unspent_txs), 1)
        self.assertEqual(self.wallet.balance, WalletBalance(0, TOKENS))

        # pass inputs and outputs to prepare_transaction, but not the input keys
        # spend output last transaction
        input_info = WalletInputInfo(tx1.hash, 0, None)
        new_address3 = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address3), TOKENS, timelock=None)
        tx2 = self.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs=[input_info], outputs=[out])
        tx2.storage = self.tx_storage
        tx2.update_hash()
        tx2.verify_script(tx2.inputs[0], tx1)
        self.wallet.on_new_tx(tx2)
        self.assertEqual(len(self.wallet.spent_txs), 2)
        self.assertEqual(self.wallet.balance, WalletBalance(0, TOKENS))

        # Test getting more unused addresses than the gap limit
        for _ in range(3):
            self.wallet.get_unused_address()

    def test_insuficient_funds(self):
        # create transaction spending some value
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(self.wallet.decode_address(new_address), TOKENS, timelock=None)
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
        self.wallet.unlock(tx_storage=self.tx_storage, words=words)

        self.assertFalse(self.wallet.is_locked())
        self.assertEqual(address, self.wallet.get_unused_address())

    def test_exceptions(self):
        with self.assertRaises(ValueError):
            HDWallet(word_count=3)
