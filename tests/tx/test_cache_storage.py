from hathor.daa import TestMode, _set_test_mode
from hathor.transaction import Transaction, TransactionMetadata
from hathor.transaction.storage import TransactionCacheStorage, TransactionMemoryStorage
from tests import unittest
from tests.utils import add_new_blocks, add_new_transactions

CACHE_SIZE = 5


class BaseCacheStorageTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        store = TransactionMemoryStorage()
        self.cache_storage = TransactionCacheStorage(store, self.clock, capacity=5)
        self.cache_storage._manually_initialize()
        self.cache_storage.pre_init()

        self.genesis = self.cache_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # Save genesis metadata
        self.cache_storage.save_transaction(self.genesis_txs[0], only_metadata=True)

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

    def test_read_moves_to_end(self):
        # when we read a tx from cache, it should be moved to the end of cache so it's evicted later
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for i in range(CACHE_SIZE):
            self.cache_storage.save_transaction(txs[i])

        # first tx added would be the first to leave cache if we add one more tx
        # let's read it from cache so it goes to the end
        self.cache_storage.get_transaction(txs[0].hash)

        # add a new tx to cache, so it will evict a tx
        self.cache_storage.save_transaction(txs[-1])

        # first tx should be in cache
        self.assertIn(txs[0].hash, self.cache_storage.cache)

    def test_cache_eviction(self):
        # tests we're evicting the oldest tx from cache
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for i in range(CACHE_SIZE):
            self.cache_storage.save_transaction(txs[i])

        # next save should evict first tx
        self.cache_storage.save_transaction(txs[CACHE_SIZE])
        self.assertNotIn(txs[0].hash, self.cache_storage.cache)
        self.assertIn(txs[CACHE_SIZE].hash, self.cache_storage.cache)
        self.assertEqual(CACHE_SIZE, len(self.cache_storage.cache))

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

    def test_topological_sort_dfs(self):
        _set_test_mode(TestMode.TEST_ALL_WEIGHT)
        add_new_blocks(self.manager, 11, advance_clock=1)
        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]

        total = 0
        for tx in self.cache_storage._run_topological_sort_dfs(root=tx, visited=dict()):
            total += 1
        self.assertEqual(total, 5)


class SyncV1CacheStorageTest(unittest.SyncV1Params, BaseCacheStorageTest):
    __test__ = True


class SyncV2CacheStorageTest(unittest.SyncV2Params, BaseCacheStorageTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeCacheStorageTest(unittest.SyncBridgeParams, SyncV2CacheStorageTest):
    pass
