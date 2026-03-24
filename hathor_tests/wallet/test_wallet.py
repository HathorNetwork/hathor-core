import shutil
import tempfile
from collections import defaultdict

from cryptography.hazmat.primitives import serialization

from hathor.crypto.util import decode_address, get_address_b58_from_public_key, get_private_key_bytes
from hathor.simulator.utils import add_new_block
from hathor.transaction import Transaction, TxInput
from hathor.wallet import Wallet
from hathor.wallet.base_wallet import WalletBalance, WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InsufficientFunds, InvalidAddress, OutOfUnusedAddresses, WalletLocked
from hathor.wallet.keypair import KeyPair
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key

BLOCK_REWARD = 300

PASSWORD = b'passwd'


class BasicWalletTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.mkdtemp()
        self.manager = self.create_peer('testnet', unlock_wallet=True)
        self.storage = self.manager.tx_storage
        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.directory)

    def test_wallet_keys_storage(self):
        w = Wallet(directory=self.directory)
        # Testing password error not in bytes
        with self.assertRaises(ValueError):
            w.unlock('testpass')
        w.unlock(b'testpass')
        w.generate_keys()
        # Using one address to save used/unused addresses in the file
        w.get_unused_address()
        w._write_keys_to_file()
        # wallet 2 will read from saved file
        w2 = Wallet(directory=self.directory)
        w2._manually_initialize()
        for address, key in w.keys.items():
            key2 = w2.keys.pop(address)
            self.assertEqual(key, key2)

    def test_wallet_create_transaction(self):
        from hathor.transaction.validation_state import ValidationState

        genesis_private_key_bytes = get_private_key_bytes(
            self.genesis_private_key,
            encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD)
        )
        genesis_address = get_address_b58_from_public_key(self.genesis_public_key)
        # create wallet with genesis block key
        key_pair = KeyPair(private_key_bytes=genesis_private_key_bytes, address=genesis_address, used=True)
        keys = {}
        keys[key_pair.address] = key_pair
        w = Wallet(keys=keys, directory=self.directory)
        w.unlock(PASSWORD)
        genesis_blocks = [tx for tx in self.storage.get_all_genesis() if tx.is_block]
        genesis_block = genesis_blocks[0]
        genesis_value = sum([output.value for output in genesis_block.outputs])

        # wallet will receive genesis block and store in unspent_tx
        w.on_new_tx(genesis_block)
        for index in range(len(genesis_block.outputs)):
            utxo = w.unspent_txs[self._settings.HATHOR_TOKEN_UID].get((genesis_block.hash, index))
            self.assertIsNotNone(utxo)
        self.assertEqual(w.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, genesis_value))

        # create transaction spending this value, but sending to same wallet
        add_blocks_unlock_reward(self.manager)
        new_address = w.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), 100, timelock=None)
        tx1 = w.prepare_transaction_compute_inputs(Transaction, [out], self.storage)
        tx1.storage = self.storage
        tx1.update_hash()
        tx1.get_metadata().validation = ValidationState.FULL
        tx1.init_static_metadata_from_storage(self._settings, self.storage)
        self.storage.save_transaction(tx1)
        w.on_new_tx(tx1)
        self.assertEqual(len(w.spent_txs), 1)
        self.assertEqual(w.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, genesis_value))

        # pass inputs and outputs to prepare_transaction, but not the input keys
        # spend output last transaction
        input_info = WalletInputInfo(tx1.hash, 1, None)
        new_address = w.get_unused_address()
        key2 = w.keys[new_address]
        out = WalletOutputInfo(decode_address(key2.address), 100, timelock=None)
        tx2 = w.prepare_transaction_incomplete_inputs(Transaction, inputs=[input_info],
                                                      outputs=[out], tx_storage=self.storage)
        tx2.storage = self.storage
        tx2.update_hash()
        tx2.get_metadata().validation = ValidationState.FULL
        tx2.init_static_metadata_from_storage(self._settings, self.storage)
        self.storage.save_transaction(tx2)
        w.on_new_tx(tx2)
        self.assertEqual(len(w.spent_txs), 2)
        self.assertEqual(w.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, genesis_value))

        # test keypair exception
        with self.assertRaises(WalletLocked):
            key_pair.get_private_key(None)

    def test_block_increase_balance(self):
        # generate a new block and check if we increase balance
        w = Wallet(directory=self.directory)
        w.unlock(PASSWORD)
        new_address = w.get_unused_address()
        key = w.keys[new_address]
        out = WalletOutputInfo(decode_address(key.address), BLOCK_REWARD, timelock=None)
        tx = w.prepare_transaction(Transaction, inputs=[], outputs=[out])
        tx.update_hash()
        w.on_new_tx(tx)
        utxo = w.unspent_txs[self._settings.HATHOR_TOKEN_UID].get((tx.hash, 0))
        self.assertIsNotNone(utxo)
        self.assertEqual(w.balance[self._settings.HATHOR_TOKEN_UID], WalletBalance(0, BLOCK_REWARD))

    def test_locked(self):
        # generate a new block and check if we increase balance
        w = Wallet(directory=self.directory)
        with self.assertRaises(OutOfUnusedAddresses):
            w.get_unused_address()

        # now it should work
        w.unlock(PASSWORD)
        w.get_unused_address()

        # lock wallet and fake that there are no more unused keys
        w.unused_keys = set()
        w.lock()
        with self.assertRaises(OutOfUnusedAddresses):
            w.get_unused_address()

        with self.assertRaises(WalletLocked):
            w.generate_keys()

    def test_insuficient_funds(self):
        w = Wallet(directory=self.directory)
        w.unlock(PASSWORD)

        # create transaction spending some value
        new_address = w.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), 100, timelock=None)
        with self.assertRaises(InsufficientFunds):
            w.prepare_transaction_compute_inputs(Transaction, [out], self.storage)

    def test_invalid_address(self):
        w = Wallet(directory=self.directory)
        w.unlock(PASSWORD)

        # creating valid address
        valid_address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        WalletOutputInfo(decode_address(valid_address), 100, None)

        # creating invalid address
        invalid_address = '5d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        with self.assertRaises(InvalidAddress):
            WalletOutputInfo(decode_address(invalid_address), 100, None)

        # invalid address (checksum invalid)
        invalid_address2 = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1Bfnq'
        with self.assertRaises(InvalidAddress):
            WalletOutputInfo(decode_address(invalid_address2), 100, None)

    def test_separate_inputs(self):
        block = add_new_block(self.manager, advance_clock=5)
        my_input = TxInput(block.hash, 0, b'')
        genesis_blocks = [tx for tx in self.storage.get_all_genesis() if tx.is_block]
        genesis_block = genesis_blocks[0]
        other_input = TxInput(genesis_block.hash, 0, b'')
        my_inputs, other_inputs = self.manager.wallet.separate_inputs([my_input, other_input], self.manager.tx_storage)
        self.assertEqual(len(my_inputs), 1)
        self.assertEqual(my_inputs[0], my_input)
        self.assertEqual(len(other_inputs), 1)
        self.assertEqual(other_inputs[0], other_input)

    def test_create_token_transaction(self):
        add_new_block(self.manager, advance_clock=5)
        add_blocks_unlock_reward(self.manager)
        tx = create_tokens(self.manager)

        tokens_created = tx.outputs[0].value
        token_uid = tx.tokens[0]
        address_b58 = self.manager.wallet.get_unused_address()
        address = decode_address(address_b58)

        _, hathor_balance = self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID]
        # prepare tx with hathors and another token
        # hathor tx
        hathor_out = WalletOutputInfo(address, hathor_balance, None)
        # token tx
        token_out = WalletOutputInfo(address, tokens_created - 20, None, token_uid.hex())

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, [hathor_out, token_out],
                                                                     self.storage)
        tx2.storage = self.manager.tx_storage
        tx2.timestamp = tx.timestamp + 1
        tx2.parents = self.manager.get_new_tx_parents()
        self.manager.cpu_mining_service.resolve(tx2)
        tx2.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        self.manager.verification_service.verify(tx2, self.get_verification_params(self.manager))

        self.assertNotEqual(len(tx2.inputs), 0)
        token_dict = defaultdict(int)
        for _input in tx2.inputs:
            output_tx = self.manager.tx_storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_uid = output_tx.get_token_uid(output.get_token_index())
            token_dict[token_uid] += output.value

        # make sure balance is the same and we've checked both balances
        did_enter = 0
        for token_uid, value in token_dict.items():
            if token_uid == self._settings.HATHOR_TOKEN_UID:
                self.assertEqual(value, hathor_balance)
                did_enter += 1
            elif token_uid == token_uid:
                self.assertEqual(value, tokens_created)
                did_enter += 1

        self.assertEqual(did_enter, 2)

    def test_prepare_transaction(self):
        block = add_new_block(self.manager, advance_clock=5)
        w = self.manager.wallet
        new_address = w.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), 1, timelock=None)
        with self.assertRaises(InsufficientFunds):
            w.prepare_transaction_compute_inputs(Transaction, [out], self.storage, timestamp=block.timestamp)

        # now it should work
        add_blocks_unlock_reward(self.manager)
        w.prepare_transaction_compute_inputs(Transaction, [out], self.storage)

    def test_maybe_spent_txs(self):
        add_new_block(self.manager, advance_clock=15)
        blocks = add_blocks_unlock_reward(self.manager)
        w = self.manager.wallet
        new_address = w.get_unused_address()
        out = WalletOutputInfo(decode_address(new_address), 1, timelock=None)
        tx1 = w.prepare_transaction_compute_inputs(Transaction, [out], self.storage)
        self.assertEqual(len(tx1.inputs), 1)
        _input = tx1.inputs[0]
        key = (_input.tx_id, _input.index)
        self.assertNotIn(key, w.unspent_txs[self._settings.HATHOR_TOKEN_UID])
        self.assertIn(key, w.maybe_spent_txs[self._settings.HATHOR_TOKEN_UID])
        self.run_to_completion()
        self.assertIn(key, w.unspent_txs[self._settings.HATHOR_TOKEN_UID])
        self.assertEqual(0, len(w.maybe_spent_txs[self._settings.HATHOR_TOKEN_UID]))

        # when we receive the new tx it will remove from maybe_spent
        tx2 = w.prepare_transaction_compute_inputs(Transaction, [out], self.storage)
        tx2.storage = self.manager.tx_storage
        tx2.timestamp = blocks[-1].timestamp + 1
        tx2.parents = self.manager.get_new_tx_parents(tx2.timestamp)
        tx2.weight = 1
        self.manager.cpu_mining_service.resolve(tx2)
        self.assertTrue(self.manager.on_new_tx(tx2))
        self.clock.advance(2)
        self.assertEqual(0, len(w.maybe_spent_txs[self._settings.HATHOR_TOKEN_UID]))
