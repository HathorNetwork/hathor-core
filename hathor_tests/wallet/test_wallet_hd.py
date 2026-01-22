from unittest.mock import Mock

from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_block
from hathor.transaction import Transaction
from hathor.verification.verification_params import VerificationParams
from hathor.wallet import HDWallet
from hathor.wallet.base_wallet import WalletBalance, WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InsufficientFunds
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class WalletHDTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = HDWallet(gap_limit=2)
        self.wallet._manually_initialize()
        self.manager = self.create_peer('testnet', wallet=self.wallet, unlock_wallet=False)
        self.tx_storage = self.manager.tx_storage
        self.wallet.unlock(tx_storage=self.tx_storage)

        self.BLOCK_TOKENS = self.manager.get_tokens_issued_per_block(1)
        self.TOKENS = self.BLOCK_TOKENS

    def test_transaction_and_balance(self):
        from hathor.transaction.validation_state import ValidationState

        # generate a new block and check if we increase balance
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), self.TOKENS, timelock=None)
        block = add_new_block(self.manager, advance_clock=1)
        self.manager.verification_service.verify(block, self.get_verification_params(self.manager))
        utxo = self.wallet.unspent_txs[self._settings.HATHOR_TOKEN_UID].get((block.hash, 0))
        self.assertIsNotNone(utxo)
        self.assertEqual(self.wallet.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, self.BLOCK_TOKENS))

        # create transaction spending this value, but sending to same wallet
        add_blocks_unlock_reward(self.manager)
        new_address2 = self.wallet.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address2), self.TOKENS, timelock=None)
        tx1 = self.wallet.prepare_transaction_compute_inputs(Transaction, [out], self.tx_storage)
        tx1.update_hash()
        verifier = self.manager.verification_service.verifiers.tx
        params = VerificationParams.default_for_mempool(best_block=Mock())
        verifier.verify_script(tx=tx1, input_tx=tx1.inputs[0], spent_tx=block, params=params)
        tx1.storage = self.tx_storage
        tx1.get_metadata().validation = ValidationState.FULL
        self.wallet.on_new_tx(tx1)
        tx1.init_static_metadata_from_storage(self._settings, self.tx_storage)
        self.tx_storage.save_transaction(tx1)
        self.assertEqual(len(self.wallet.spent_txs), 1)
        utxo = self.wallet.unspent_txs[self._settings.HATHOR_TOKEN_UID].get((tx1.hash, 0))
        self.assertIsNotNone(utxo)
        self.assertEqual(self.wallet.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, self.TOKENS))

        # pass inputs and outputs to prepare_transaction, but not the input keys
        # spend output last transaction
        input_info = WalletInputInfo(tx1.hash, 0, None)
        new_address3 = self.wallet.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address3), self.TOKENS, timelock=None)
        tx2 = self.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs=[input_info],
                                                                outputs=[out], tx_storage=self.tx_storage)
        tx2.storage = self.tx_storage
        tx2.update_hash()
        tx2.storage = self.tx_storage
        verifier.verify_script(tx=tx2, input_tx=tx2.inputs[0], spent_tx=tx1, params=params)
        tx2.get_metadata().validation = ValidationState.FULL
        tx2.init_static_metadata_from_storage(self._settings, self.tx_storage)
        self.tx_storage.save_transaction(tx2)
        self.wallet.on_new_tx(tx2)
        self.assertEqual(len(self.wallet.spent_txs), 2)
        self.assertEqual(self.wallet.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, self.TOKENS))

        # Test getting more unused addresses than the gap limit
        for i in range(3):
            kwargs = {'mark_as_used': True}
            if i == 2:
                # Last one we dont mark as used
                kwargs['mark_as_used'] = False

            self.wallet.get_unused_address(**kwargs)

    def test_insuficient_funds(self):
        add_blocks_unlock_reward(self.manager)
        # create transaction spending some value
        new_address = self.wallet.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), self.TOKENS, timelock=None)
        with self.assertRaises(InsufficientFunds):
            self.wallet.prepare_transaction_compute_inputs(Transaction, [out], self.tx_storage)

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
