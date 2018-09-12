import unittest
import os
import json
import base58
import base64
import tempfile
import shutil
from hathor.transaction import Transaction
from hathor.transaction.genesis import genesis_transactions
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet import Wallet
from hathor.wallet.wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.keypair import KeyPair
from hathor.wallet.exceptions import WalletLocked, OutOfUnusedAddresses, InsuficientFunds
from hathor.crypto.util import get_private_key_from_bytes, get_address_b58_from_public_key, get_private_key_bytes
from cryptography.hazmat.primitives import serialization

BLOCK_REWARD = 300

PASSWORD = 'passwd'


class BasicWallet(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
        # read genesis keys
        filepath = os.path.join(os.getcwd(), 'hathor/wallet/genesis_keys.json')
        dict_data = None
        with open(filepath, 'r') as json_file:
            dict_data = json.loads(json_file.read())
        b64_private_key = dict_data['private_key']
        private_key_bytes = base64.b64decode(b64_private_key)
        self.genesis_private_key = get_private_key_from_bytes(private_key_bytes)
        self.genesis_address = get_address_b58_from_public_key(self.genesis_private_key.public_key())
        self.genesis_private_key_bytes = get_private_key_bytes(
            self.genesis_private_key,
            encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode())
        )

    def tearDown(self):
        shutil.rmtree(self.directory)

    def test_wallet_keys_storage(self):
        w = Wallet(directory=self.directory)
        w.unlock('testpass')
        w.generate_keys()
        w._write_keys_to_file()
        # wallet 2 will read from saved file
        w2 = Wallet(directory=self.directory)
        w2.read_keys_from_file()
        for address, key in w.keys.items():
            key2 = w2.keys.pop(address)
            self.assertEqual(key, key2)

    def test_wallet_create_transaction(self):
        # create wallet with genesis block key
        key_pair = KeyPair(private_key_bytes=self.genesis_private_key_bytes, address=self.genesis_address, used=True)
        keys = {}
        keys[key_pair.address] = key_pair
        w = Wallet(keys=keys, directory=self.directory)
        w.unlock(PASSWORD)
        genesis_blocks = [tx for tx in genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]
        genesis_value = genesis_block.outputs[0].value

        # wallet will receive genesis block and store in unspent_tx
        w.on_new_tx(genesis_block)
        self.assertEqual(len(list(w.unspent_txs.values())[0]), 1)
        self.assertEqual(w.balance, genesis_value)

        # create transaction spending this value, but sending to same wallet
        new_address = w.get_unused_address()
        out = WalletOutputInfo(base58.b58decode(new_address), 100)
        tx1 = w.prepare_transaction_compute_inputs(Transaction, outputs=[out])
        tx1.update_hash()
        w.on_new_tx(tx1)
        self.assertEqual(len(w.spent_txs), 1)
        self.assertEqual(w.balance, genesis_value)

        # pass inputs and outputs to prepare_transaction, but not the input keys
        # spend output last transaction
        input_info = WalletInputInfo(tx1.hash, 1, None)
        new_address = w.get_unused_address()
        key2 = w.keys[new_address]
        out = WalletOutputInfo(base58.b58decode(key2.address), 100)
        tx2 = w.prepare_transaction_incomplete_inputs(Transaction, inputs=[input_info], outputs=[out])
        tx2.update_hash()
        w.on_new_tx(tx2)
        self.assertEqual(len(w.spent_txs), 2)
        self.assertEqual(w.balance, genesis_value)

        # test wallet history storage
        w.save_history_to_file()
        w2 = Wallet(directory=self.directory)
        w2.read_history_from_file()
        self.assertEqual(w.balance, w2.balance)
        self.assertEqual(len(w.spent_txs), len(w.spent_txs))
        self.assertEqual(len(w.unspent_txs), len(w2.unspent_txs))

    def test_block_increase_balance(self):
        # generate a new block and check if we increase balance
        w = Wallet(directory=self.directory)
        w.unlock(PASSWORD)
        new_address = w.get_unused_address()
        key = w.keys[new_address]
        out = WalletOutputInfo(base58.b58decode(key.address), BLOCK_REWARD)
        tx = w.prepare_transaction(Transaction, inputs=[], outputs=[out])
        tx.update_hash()
        w.on_new_tx(tx)
        self.assertEqual(len(w.unspent_txs[new_address]), 1)
        self.assertEqual(w.balance, BLOCK_REWARD)

    def test_replay_from_file(self):
        # create wallet with genesis block key
        key_pair = KeyPair(private_key_bytes=self.genesis_private_key_bytes, address=self.genesis_address, used=True)
        keys = {}
        keys[key_pair.address] = key_pair
        w = Wallet(keys=keys, directory=self.directory)
        w.unlock(PASSWORD)
        genesis_blocks = [tx for tx in genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]
        genesis_value = genesis_block.outputs[0].value

        # memory storage will only have genesis transactions
        memory_storage = TransactionMemoryStorage()
        w.replay_from_storage(memory_storage)
        self.assertEqual(len(w.unspent_txs[key_pair.address]), 1)
        self.assertEqual(w.balance, genesis_value)

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
        out = WalletOutputInfo(base58.b58decode(new_address), 100)
        with self.assertRaises(InsuficientFunds):
            w.prepare_transaction_compute_inputs(Transaction, outputs=[out])


if __name__ == '__main__':
    unittest.main()
