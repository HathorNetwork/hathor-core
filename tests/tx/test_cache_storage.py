import collections

from twisted.internet.defer import inlineCallbacks

from hathor.manager import TestMode
from hathor.transaction import Block, Transaction, TransactionMetadata, TxOutput
from hathor.transaction.storage import TransactionCacheStorage, TransactionMemoryStorage
from tests import unittest
from tests.utils import add_new_blocks, add_new_transactions

CACHE_SIZE = 5


class BasicTransaction(unittest.TestCase):
    def setUp(self):
        super().setUp()

        store = TransactionMemoryStorage()
        self.cache_storage = TransactionCacheStorage(store, self.clock, capacity=5)
        self.cache_storage._manually_initialize()
        self.cache_storage.start()

        self.genesis = self.cache_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # Save genesis metadata
        self.cache_storage.save_transaction_deferred(self.genesis_txs[0], only_metadata=True)

        # self.manager = HathorManager(self.reactor, tx_storage=self.cache_storage, wallet=wallet)
        self.manager = self.create_peer('testnet', tx_storage=self.cache_storage, unlock_wallet=True)

    def tearDown(self):
        super().tearDown()

    def _get_new_tx(self, nonce):
        tx = Transaction(nonce=nonce, storage=self.cache_storage)
        tx.update_hash()
        meta = TransactionMetadata(hash=tx.hash)
        tx._metadata = meta
        return tx

    def test_write_read(self):
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        txs2 = [self.cache_storage.get_transaction(tx.hash) for tx in txs]

        self.assertEqual(txs, txs2)

    def test_dirty_set(self):
        txs = [self._get_new_tx(nonce) for nonce in range(CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        for tx in txs:
            self.assertIn(tx.hash, self.cache_storage.dirty_txs)

        # should flush to disk and empty dirty set
        self.cache_storage._flush_to_storage(self.cache_storage.dirty_txs.copy())
        self.assertEqual(0, len(self.cache_storage.dirty_txs))

    def test_capacity(self):
        # cache should not grow over its capacity
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        self.assertEqual(CACHE_SIZE, len(self.cache_storage.cache))

    def test_read_adds_to_cache(self):
        # make sure reading also adds to cache, not only writes
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        # by now, tx[0] will already have left the cache
        self.assertNotIn(txs[0].hash, self.cache_storage.cache)

        # read tx
        self.cache_storage.get_transaction(txs[0].hash)

        # now it should be in cache
        self.assertIn(txs[0].hash, self.cache_storage.cache)

    def test_flush_thread(self):
        txs = [self._get_new_tx(nonce) for nonce in range(CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        for tx in txs:
            self.assertIn(tx.hash, self.cache_storage.dirty_txs)

        # Flush deferred is not None
        self.assertIsNotNone(self.cache_storage.flush_deferred)
        last_flush_deferred = self.cache_storage.flush_deferred
        self.cache_storage._start_flush_thread()
        self.assertEqual(last_flush_deferred, self.cache_storage.flush_deferred)

        # We flush the cache and flush_deferred becomes None
        self.cache_storage._cb_flush_thread(self.cache_storage.dirty_txs.copy())
        self.assertIsNone(self.cache_storage.flush_deferred)
        # After the interval it becomes not None again
        self.clock.advance(10)
        self.assertIsNotNone(self.cache_storage.flush_deferred)

        # If an err occurs, it will become None again and then not None after the interval
        self.cache_storage._err_flush_thread('')
        self.assertIsNone(self.cache_storage.flush_deferred)
        self.clock.advance(5)
        self.assertIsNotNone(self.cache_storage.flush_deferred)

        # Remove element from cache to test a part of the code
        del self.cache_storage.cache[next(iter(self.cache_storage.dirty_txs))]
        self.cache_storage._flush_to_storage(self.cache_storage.dirty_txs.copy())

    def test_deferred_methods(self):
        for _ in self._test_deferred_methods():
            pass

    @inlineCallbacks
    def _test_deferred_methods(self):
        # Testing without cloning
        self.cache_storage._clone_if_needed = False

        block_parents = [tx.hash for tx in self.genesis]
        output = TxOutput(200, bytes.fromhex('1e393a5ce2ff1c98d4ff6892f2175100f2dad049'))
        obj = Block(timestamp=1539271491, weight=12, outputs=[output], parents=block_parents, nonce=100781,
                    storage=self.cache_storage)
        obj.resolve()

        self.cache_storage.save_transaction_deferred(obj)

        loaded_obj1 = yield self.cache_storage.get_transaction_deferred(obj.hash)

        metadata_obj1_def = yield self.cache_storage.get_metadata_deferred(obj.hash)
        metadata_obj1 = obj.get_metadata()
        self.assertEqual(metadata_obj1_def, metadata_obj1)
        metadata_error = yield self.cache_storage.get_metadata_deferred(
            bytes.fromhex('0001569c85fffa5782c3979e7d68dce1d8d84772505a53ddd76d636585f3977e'))
        self.assertIsNone(metadata_error)

        self.cache_storage._flush_to_storage(self.cache_storage.dirty_txs.copy())
        self.cache_storage.cache = collections.OrderedDict()
        loaded_obj2 = yield self.cache_storage.get_transaction_deferred(obj.hash)

        self.assertEqual(loaded_obj1, loaded_obj2)

        self.assertTrue((yield self.cache_storage.transaction_exists_deferred(obj.hash)))
        self.assertFalse((yield self.cache_storage.transaction_exists_deferred(
            '0001569c85fffa5782c3979e7d68dce1d8d84772505a53ddd76d636585f3977e')))

        self.assertFalse(
            self.cache_storage.transaction_exists('0001569c85fffa5782c3979e7d68dce1d8d84772505a53ddd76d636585f3977e'))

        self.assertEqual(obj, loaded_obj1)
        self.assertEqual(obj.is_block, loaded_obj1.is_block)

        count = yield self.cache_storage.get_count_tx_blocks_deferred()
        self.assertEqual(count, 4)

        all_transactions = yield self.cache_storage.get_all_transactions_deferred()
        total = 0
        for tx in all_transactions:
            total += 1
        self.assertEqual(total, 4)

    def test_topological_sort_dfs(self):
        self.manager.test_mode = TestMode.TEST_ALL_WEIGHT
        add_new_blocks(self.manager, 1, advance_clock=1)
        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]

        total = 0
        for tx in self.cache_storage._topological_sort_dfs(root=tx, visited=dict()):
            total += 1
        self.assertEqual(total, 5)


if __name__ == '__main__':
    unittest.main()
