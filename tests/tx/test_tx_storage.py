import os
import shutil
import tempfile
import time
import unittest

from twisted.internet.task import Clock

from hathor.constants import STORAGE_SUBFOLDERS
from hathor.manager import TestMode
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.storage import (
    TransactionBinaryStorage,
    TransactionCacheStorage,
    TransactionCompactStorage,
    TransactionMemoryStorage,
    TransactionSubprocessStorage,
)
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.wallet import Wallet
from tests.utils import add_new_blocks, add_new_transactions, start_remote_storage


class _BaseTransactionStorageTest:
    class _TransactionStorageTest(unittest.TestCase):
        def setUp(self, tx_storage, reactor=None):
            if not reactor:
                self.reactor = Clock()
            else:
                self.reactor = reactor
            self.reactor.advance(time.time())
            self.tx_storage = tx_storage
            tx_storage._manually_initialize()
            self.genesis = self.tx_storage.get_all_genesis()
            self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
            self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

            from hathor.manager import HathorManager
            self.tmpdir = tempfile.mkdtemp(dir='/tmp/')
            wallet = Wallet(directory=self.tmpdir)
            wallet.unlock(b'teste')
            self.manager = HathorManager(self.reactor, tx_storage=self.tx_storage, wallet=wallet)

            block_parents = [tx.hash for tx in self.genesis]
            output = TxOutput(200, bytes.fromhex('1e393a5ce2ff1c98d4ff6892f2175100f2dad049'))
            self.block = Block(timestamp=1539271491, weight=12, outputs=[output], parents=block_parents, nonce=100781,
                               storage=tx_storage)
            self.block.resolve()

            tx_parents = [tx.hash for tx in self.genesis_txs]
            tx_input = TxInput(
                tx_id=bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902'), index=0,
                data=bytes.fromhex('46304402203470cb9818c9eb842b0c433b7e2b8aded0a51f5903e971649e870763d0266a'
                                   'd2022049b48e09e718c4b66a0f3178ef92e4d60ee333d2d0e25af8868acf5acbb35aaa583'
                                   '056301006072a8648ce3d020106052b8104000a034200042ce7b94cba00b654d4308f8840'
                                   '7345cacb1f1032fb5ac80407b74d56ed82fb36467cb7048f79b90b1cf721de57e942c5748'
                                   '620e78362cf2d908e9057ac235a63'))

            self.tx = Transaction(
                timestamp=1539271493, weight=10, nonce=932049, inputs=[tx_input], outputs=[output], parents=tx_parents,
                tokens=[bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')],
                storage=tx_storage)
            self.tx.resolve()

            # Disable weakref to test the internal methods. Otherwise, most methods return objects from weakref.
            self.tx_storage._disable_weakref()

        def tearDown(self):
            shutil.rmtree(self.tmpdir)

        def test_genesis(self):
            self.assertEqual(1, len(self.genesis_blocks))
            self.assertEqual(2, len(self.genesis_txs))
            for tx in self.genesis:
                tx.verify()

            for tx in self.genesis:
                tx2 = self.tx_storage.get_transaction(tx.hash)
                self.assertEqual(tx, tx2)
                self.assertTrue(self.tx_storage.transaction_exists(tx.hash))

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

        def validate_save(self, obj):
            self.tx_storage.save_transaction(obj)

            loaded_obj1 = self.tx_storage.get_transaction(obj.hash)

            self.assertTrue(self.tx_storage.transaction_exists(obj.hash))

            self.assertEqual(obj, loaded_obj1)
            self.assertEqual(obj.is_block, loaded_obj1.is_block)

            # Testing add and remove from cache
            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertTrue(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertTrue(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

            self.tx_storage._del_from_cache(obj)

            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertFalse(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertFalse(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

            self.tx_storage._add_to_cache(obj)
            if self.tx_storage.with_index:
                if obj.is_block:
                    self.assertTrue(obj.hash in self.tx_storage.block_index.tips_index.tx_last_interval)
                else:
                    self.assertTrue(obj.hash in self.tx_storage.tx_index.tips_index.tx_last_interval)

        def test_save_block(self):
            self.validate_save(self.block)

        def test_save_tx(self):
            self.validate_save(self.tx)

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
            if parents is not None:
                block.parents = parents
            block.weight = 10
            self.assertTrue(block.resolve())
            block.verify()
            self.manager.tx_storage.save_transaction(block)
            self.reactor.advance(5)
            return block

        def test_topological_sort(self):
            self.manager.test_mode = TestMode.TEST_ALL_WEIGHT
            add_new_blocks(self.manager, 1, advance_clock=1)
            add_new_transactions(self.manager, 1, advance_clock=1)[0]

            total = 0
            for tx in self.tx_storage._topological_sort():
                total += 1
            self.assertEqual(total, 5)

    class _RemoteStorageTest(_TransactionStorageTest):
        def setUp(self, tx_storage, reactor=None):
            tx_storage, self._server = start_remote_storage(tx_storage=tx_storage)
            super().setUp(tx_storage, reactor=reactor)

        def tearDown(self):
            self._server.stop(0)
            super().tearDown()

    class _SubprocessStorageTest(_TransactionStorageTest):
        def setUp(self, tx_storage_constructor, reactor=None):
            tx_storage = TransactionSubprocessStorage(tx_storage_constructor)
            tx_storage.start()
            super().setUp(tx_storage, reactor=reactor)

        def tearDown(self):
            self.tx_storage.stop()
            super().tearDown()


class TransactionBinaryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
        super().setUp(TransactionBinaryStorage(self.directory))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class TransactionCompactStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
        # Creating random file just to test specific part of code
        tempfile.NamedTemporaryFile(dir=self.directory, delete=True)
        super().setUp(TransactionCompactStorage(self.directory))

    def test_subfolders(self):
        # test we have the subfolders under the main tx folder
        subfolders = os.listdir(self.directory)
        self.assertEqual(STORAGE_SUBFOLDERS, len(subfolders))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class CacheBinaryStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
        store = TransactionBinaryStorage(self.directory)
        reactor = Clock()
        super().setUp(TransactionCacheStorage(store, reactor, capacity=5))

    def tearDown(self):
        shutil.rmtree(self.directory)
        super().tearDown()


class CacheCompactStorageTest(_BaseTransactionStorageTest._TransactionStorageTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp(dir='/tmp/')
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


# class SubprocessMemoryStorageTest(_BaseTransactionStorageTest._SubprocessStorageTest):
#    def setUp(self):
#        super().setUp(TransactionMemoryStorage)

# class SubprocessCacheMemoryStorageTest(_BaseTransactionStorageTest._SubprocessStorageTest):
#    def setUp(self):
#        def storage_constructor():
#            store = TransactionMemoryStorage()
#            reactor = Clock()
#            return TransactionCacheStorage(store, reactor, capacity=5)
#        super().setUp(storage_constructor)


class RemoteMemoryStorageTest(_BaseTransactionStorageTest._RemoteStorageTest):
    def setUp(self):
        super().setUp(TransactionMemoryStorage())


class RemoteCacheMemoryStorageTest(_BaseTransactionStorageTest._RemoteStorageTest):
    def setUp(self):
        store = TransactionMemoryStorage()
        reactor = Clock()
        super().setUp(TransactionCacheStorage(store, reactor, capacity=5))


if __name__ == '__main__':
    unittest.main()
