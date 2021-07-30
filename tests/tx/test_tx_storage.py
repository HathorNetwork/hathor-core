import os
import shutil
import tempfile
import time
from itertools import chain

import pytest
from twisted.internet.defer import gatherResults, inlineCallbacks
from twisted.internet.task import Clock
from twisted.internet.threads import deferToThread
from twisted.trial import unittest

from hathor.conf import HathorSettings
from hathor.daa import TestMode, _set_test_mode
from hathor.indexes import TokensIndex, WalletIndex
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import (
    TransactionBinaryStorage,
    TransactionCacheStorage,
    TransactionCompactStorage,
    TransactionMemoryStorage,
    TransactionOldRocksDBStorage,
    TransactionRocksDBStorage,
)
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.transaction_metadata import ValidationState
from hathor.wallet import Wallet
from tests.utils import (
    BURN_ADDRESS,
    MIN_TIMESTAMP,
    add_blocks_unlock_reward,
    add_new_blocks,
    add_new_transactions,
    create_tokens,
)

try:
    import rocksdb  # noqa: F401
except ImportError:
    HAS_ROCKSDB = False
else:
    HAS_ROCKSDB = True

settings = HathorSettings()


class _BaseTransactionStorageTest:
    class _TransactionStorageTest(unittest.TestCase):
        def setUp(self, tx_storage, reactor=None):
            from hathor.manager import HathorManager

            if not reactor:
                self.reactor = Clock()
            else:
                self.reactor = reactor
            self.reactor.advance(time.time())
            self.tx_storage = tx_storage
            assert tx_storage.first_timestamp > 0

            tx_storage._manually_initialize()

            self.genesis = self.tx_storage.get_all_genesis()
            self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
            self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

            self.tmpdir = tempfile.mkdtemp()
            wallet = Wallet(directory=self.tmpdir)
            wallet.unlock(b'teste')
            self.manager = HathorManager(self.reactor, tx_storage=self.tx_storage, wallet=wallet)

            self.tx_storage.wallet_index = WalletIndex(self.manager.pubsub)
            self.tx_storage.tokens_index = TokensIndex()

            block_parents = [tx.hash for tx in chain(self.genesis_blocks, self.genesis_txs)]
            output = TxOutput(200, P2PKH.create_output_script(BURN_ADDRESS))
            self.block = Block(timestamp=MIN_TIMESTAMP, weight=12, outputs=[output], parents=block_parents,
                               nonce=100781, storage=tx_storage)
            self.block.resolve()
            self.block.verify()
            self.block.get_metadata().validation = ValidationState.FULL

            tx_parents = [tx.hash for tx in self.genesis_txs]
            tx_input = TxInput(
                tx_id=self.genesis_blocks[0].hash, index=0,
                data=bytes.fromhex('46304402203470cb9818c9eb842b0c433b7e2b8aded0a51f5903e971649e870763d0266a'
                                   'd2022049b48e09e718c4b66a0f3178ef92e4d60ee333d2d0e25af8868acf5acbb35aaa583'
                                   '056301006072a8648ce3d020106052b8104000a034200042ce7b94cba00b654d4308f8840'
                                   '7345cacb1f1032fb5ac80407b74d56ed82fb36467cb7048f79b90b1cf721de57e942c5748'
                                   '620e78362cf2d908e9057ac235a63'))

            self.tx = Transaction(
                timestamp=MIN_TIMESTAMP + 2, weight=10, nonce=932049, inputs=[tx_input], outputs=[output],
                tokens=[bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')],
                parents=tx_parents, storage=tx_storage)
            self.tx.resolve()
            self.tx.get_metadata().validation = ValidationState.FULL

            # Disable weakref to test the internal methods. Otherwise, most methods return objects from weakref.
            self.tx_storage._disable_weakref()

            self.tx_storage.enable_lock()

        def tearDown(self):
            shutil.rmtree(self.tmpdir)

        def test_genesis_ref(self):
            # Enable weakref to this test only.
            self.tx_storage._enable_weakref()

            genesis_set = set(self.tx_storage.get_all_genesis())
            for tx in genesis_set:
                tx2 = self.tx_storage.get_transaction(tx.hash)
                self.assertTrue(tx is tx2)

            from hathor.transaction.genesis import _get_genesis_transactions_unsafe
            genesis_from_settings = _get_genesis_transactions_unsafe(None)
            for tx in genesis_from_settings:
                tx2 = self.tx_storage.get_transaction(tx.hash)
                self.assertTrue(tx is not tx2)
                for tx3 in genesis_set:
                    self.assertTrue(tx is not tx3)
                    if tx2 == tx3:
                        self.assertTrue(tx2 is tx3)

        def test_genesis(self):
            self.assertEqual(1, len(self.genesis_blocks))
            self.assertEqual(2, len(self.genesis_txs))
            for tx in self.genesis:
                tx.verify()

            for tx in self.genesis:
                tx2 = self.tx_storage.get_transaction(tx.hash)
                self.assertEqual(tx, tx2)
                self.assertTrue(self.tx_storage.transaction_exists(tx.hash))

        def test_get_empty_merklee_tree(self):
            # We use `first_timestamp - 1` to ensure that the merkle tree will be empty.
            self.tx_storage.get_merkle_tree(self.tx_storage.first_timestamp - 1)

        def test_first_timestamp(self):
            self.assertEqual(self.tx_storage.first_timestamp, min(x.timestamp for x in self.genesis))

        def test_storage_basic(self):
            self.assertEqual(1, self.tx_storage.get_block_count())
            self.assertEqual(2, self.tx_storage.get_tx_count())
            self.assertEqual(3, self.tx_storage.get_count_tx_blocks())

            block_parents_hash = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(1, len(block_parents_hash))
            self.assertEqual(block_parents_hash, [self.genesis_blocks[0].hash])

            tx_parents_hash = [x.data for x in self.tx_storage.get_tx_tips()]
            self.assertEqual(2, len(tx_parents_hash))
            self.assertEqual(set(tx_parents_hash), {self.genesis_txs[0].hash, self.genesis_txs[1].hash})

        def test_storage_basic_v2(self):
            self.assertEqual(1, self.tx_storage.get_block_count())
            self.assertEqual(2, self.tx_storage.get_tx_count())
            self.assertEqual(3, self.tx_storage.get_count_tx_blocks())

            block_parents_hash = self.tx_storage.get_best_block_tips()
            self.assertEqual(1, len(block_parents_hash))
            self.assertEqual(block_parents_hash, [self.genesis_blocks[0].hash])

            tx_parents_hash = self.manager.get_new_tx_parents()
            self.assertEqual(2, len(tx_parents_hash))
            self.assertEqual(set(tx_parents_hash), {self.genesis_txs[0].hash, self.genesis_txs[1].hash})

        def validate_save(self, obj):
            self.tx_storage.save_transaction(obj, add_to_indexes=True)

            loaded_obj1 = self.tx_storage.get_transaction(obj.hash)

            self.assertTrue(self.tx_storage.transaction_exists(obj.hash))

            self.assertEqual(obj, loaded_obj1)
            self.assertEqual(len(obj.get_funds_struct()), len(loaded_obj1.get_funds_struct()))
            self.assertEqual(bytes(obj), bytes(loaded_obj1))
            self.assertEqual(obj.to_json(), loaded_obj1.to_json())
            self.assertEqual(obj.is_block, loaded_obj1.is_block)

            # Testing add and remove from cache
            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertTrue(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertTrue(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

            self.tx_storage.del_from_indexes(obj, del_blocks=True)

            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertFalse(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertFalse(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

            self.tx_storage.add_to_indexes(obj)
            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertTrue(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertTrue(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

        def test_save_block(self):
            self.validate_save(self.block)

        def test_save_tx(self):
            self.validate_save(self.tx)

        def test_save_token_creation_tx(self):
            tx = create_tokens(self.manager, propagate=False)
            tx.get_metadata().validation = ValidationState.FULL
            self.validate_save(tx)

        def _validate_not_in_index(self, tx, index):
            tips = index.tips_index[self.tx.timestamp]
            self.assertNotIn(self.tx.hash, [x.data for x in tips])
            self.assertNotIn(self.tx.hash, index.tips_index.tx_last_interval)

            self.assertIsNone(index.txs_index.find_tx_index(tx))

        def _test_remove_tx_or_block(self, tx):
            self.validate_save(tx)

            self.tx_storage.remove_transaction(tx)
            with self.assertRaises(TransactionDoesNotExist):
                self.tx_storage.get_transaction(tx.hash)

            if hasattr(self.tx_storage, 'all_index'):
                self._validate_not_in_index(tx, self.tx_storage.all_index)

            if tx.is_block:
                if hasattr(self.tx_storage, 'block_index'):
                    self._validate_not_in_index(tx, self.tx_storage.block_index)
            else:
                if hasattr(self.tx_storage, 'tx_index'):
                    self._validate_not_in_index(tx, self.tx_storage.tx_index)

            # Check wallet index.
            wallet_index = self.tx_storage.wallet_index
            addresses = wallet_index._get_addresses(tx)
            for address in addresses:
                self.assertNotIn(tx.hash, wallet_index.index[address])

            # TODO Check self.tx_storage.tokens_index

            # Try to remove twice. It is supposed to do nothing.
            self.tx_storage.remove_transaction(tx)

        def test_remove_tx(self):
            self._test_remove_tx_or_block(self.tx)

        def test_remove_block(self):
            self._test_remove_tx_or_block(self.block)

        def test_shared_memory(self):
            # Enable weakref to this test only.
            self.tx_storage._enable_weakref()

            self.validate_save(self.block)
            self.validate_save(self.tx)

            for tx in [self.tx, self.block]:
                # just making sure, if it is genesis the test is wrong
                self.assertFalse(tx.is_genesis)

                # load transactions twice
                tx1 = self.tx_storage.get_transaction(tx.hash)
                tx2 = self.tx_storage.get_transaction(tx.hash)

                # naturally they should be equal, but this time so do the objects
                self.assertTrue(tx1 == tx2)
                self.assertTrue(tx1 is tx2)

                meta1 = tx1.get_metadata()
                meta2 = tx2.get_metadata()

                # and naturally the metadata too
                self.assertTrue(meta1 == meta2)
                self.assertTrue(meta1 is meta2)

        def test_get_wrong_tx(self):
            hex_error = bytes.fromhex('00001c5c0b69d13b05534c94a69b2c8272294e6b0c536660a3ac264820677024')
            with self.assertRaises(TransactionDoesNotExist):
                self.tx_storage.get_transaction(hex_error)

        def test_save_metadata(self):
            # Saving genesis metadata
            self.tx_storage.save_transaction(self.genesis_txs[0], only_metadata=True)

            tx = self.block
            # First we save to the storage
            self.tx_storage.save_transaction(tx)

            metadata = tx.get_metadata()
            metadata.spent_outputs[1].append(self.genesis_blocks[0].hash)
            random_tx = bytes.fromhex('0000222e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0f2222')
            metadata.children.append(random_tx)

            self.tx_storage.save_transaction(tx, only_metadata=True)
            tx2 = self.tx_storage.get_transaction(tx.hash)
            metadata2 = tx2.get_metadata()
            self.assertEqual(metadata, metadata2)

            total = 0
            for tx in self.tx_storage.get_all_transactions():
                total += 1

            self.assertEqual(total, 4)

        def test_storage_new_blocks(self):
            tip_blocks = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(tip_blocks, [self.genesis_blocks[0].hash])

            block1 = self._add_new_block()
            tip_blocks = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(tip_blocks, [block1.hash])

            block2 = self._add_new_block()
            tip_blocks = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(tip_blocks, [block2.hash])

            # Block3 has the same parents as block2.
            block3 = self._add_new_block(parents=block2.parents)
            tip_blocks = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(set(tip_blocks), {block2.hash, block3.hash})

            # Re-generate caches to test topological sort.
            self.tx_storage._manually_initialize()
            tip_blocks = [x.data for x in self.tx_storage.get_block_tips()]
            self.assertEqual(set(tip_blocks), {block2.hash, block3.hash})

        def test_token_list(self):
            tx = self.tx
            self.validate_save(tx)
            # 2 token uids
            tx.tokens.append(bytes.fromhex('00001c5c0b69d13b05534c94a69b2c8272294e6b0c536660a3ac264820677024'))
            tx.resolve()
            self.validate_save(tx)
            # no tokens
            tx.tokens = []
            tx.resolve()
            self.validate_save(tx)

        def _add_new_block(self, parents=None):
            block = self.manager.generate_mining_block()
            block.data = b'Testing, testing, 1, 2, 3... testing, testing...'
            if parents is not None:
                block.parents = parents
            block.weight = 10
            self.assertTrue(block.resolve())
            block.verify()
            self.manager.propagate_tx(block, fails_silently=False)
            self.reactor.advance(5)
            return block

        def test_topological_sort(self):
            _set_test_mode(TestMode.TEST_ALL_WEIGHT)
            _total = 0
            blocks = add_new_blocks(self.manager, 1, advance_clock=1)
            _total += len(blocks)
            blocks = add_blocks_unlock_reward(self.manager)
            _total += len(blocks)
            add_new_transactions(self.manager, 1, advance_clock=1)

            total = 0
            for tx in self.tx_storage._topological_sort():
                total += 1

            # added blocks + genesis txs + added tx
            self.assertEqual(total, _total + 3 + 1)

        def test_get_best_block_weight(self):
            block = self._add_new_block()
            weight = self.tx_storage.get_weight_best_block()
            self.assertEqual(block.weight, weight)

        @inlineCallbacks
        def test_concurrent_access(self):
            self.tx_storage.save_transaction(self.tx)
            self.tx_storage._enable_weakref()

            def handle_error(err):
                self.fail('Error resolving concurrent access deferred. {}'.format(err))

            deferreds = []
            for i in range(5):
                d = deferToThread(self.tx_storage.get_transaction, self.tx.hash)
                d.addErrback(handle_error)
                deferreds.append(d)

            self.reactor.advance(3)
            yield gatherResults(deferreds)
            self.tx_storage._disable_weakref()

        def test_full_verification_attribute(self):
            self.assertFalse(self.tx_storage.is_running_full_verification())
            self.tx_storage.start_full_verification()
            self.assertTrue(self.tx_storage.is_running_full_verification())
            self.tx_storage.finish_full_verification()
            self.assertFalse(self.tx_storage.is_running_full_verification())

        def test_key_value_attribute(self):
            attr = 'test'
            val = 'a'

            # Try to get a key that does not exist
            self.assertIsNone(self.tx_storage.get_value(attr))

            # Try to remove this key that does not exist
            self.tx_storage.remove_value(attr)

            # Add the key/value
            self.tx_storage.add_value(attr, val)

            # Get correct value
            self.assertEqual(self.tx_storage.get_value(attr), val)

            # Remove the key
            self.tx_storage.remove_value(attr)

            # Key should not exist again
            self.assertIsNone(self.tx_storage.get_value(attr))


class TransactionBinaryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        super().setUp(TransactionBinaryStorage(self.directory))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class TransactionCompactStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        # Creating random file just to test specific part of code
        tempfile.NamedTemporaryFile(dir=self.directory, delete=True)
        super().setUp(TransactionCompactStorage(self.directory))

    def test_subfolders(self):
        # test we have the subfolders under the main tx folder
        subfolders_path = os.path.join(self.directory, 'tx')
        subfolders = os.listdir(subfolders_path)
        self.assertEqual(settings.STORAGE_SUBFOLDERS, len(subfolders))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class CacheBinaryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        store = TransactionBinaryStorage(self.directory)
        reactor = Clock()
        super().setUp(TransactionCacheStorage(store, reactor, capacity=5))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class CacheCompactStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        # Creating random file just to test specific part of code
        tempfile.NamedTemporaryFile(dir=self.directory, delete=True)
        store = TransactionCompactStorage(self.directory)
        reactor = Clock()
        super().setUp(TransactionCacheStorage(store, reactor, capacity=5))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class TransactionMemoryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        super().setUp(TransactionMemoryStorage())


class CacheMemoryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        store = TransactionMemoryStorage()
        reactor = Clock()
        super().setUp(TransactionCacheStorage(store, reactor, capacity=5))


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class TransactionOldRocksDBStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        super().setUp(TransactionOldRocksDBStorage(self.directory))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class TransactionRocksDBStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        super().setUp(TransactionRocksDBStorage(self.directory))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()
