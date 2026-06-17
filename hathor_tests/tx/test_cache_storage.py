from unittest.mock import Mock

from twisted.internet.task import deferLater

from hathor.daa import TestMode
from hathor.reactor import get_global_reactor
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TransactionMetadata
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor_tests import unittest
from hathor_tests.utils import add_new_transactions

CACHE_SIZE = 5


class CacheStorageTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        builder = self.get_builder() \
            .use_tx_storage_cache(capacity=5) \
            .set_wallet(self._create_test_wallet(unlocked=True))
        self.manager = self.create_peer_from_builder(builder)
        self.cache_storage = self.manager.tx_storage
        self.assertIsInstance(self.cache_storage, TransactionRocksDBStorage)
        self.assertIsNotNone(self.cache_storage.cache_data)

        self.genesis = self.cache_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # Save genesis metadata
        self.cache_storage.save_transaction(self.genesis_txs[0], only_metadata=True)

    def tearDown(self):
        super().tearDown()

    def _get_new_tx(self, nonce):
        from hathor.transaction.validation_state import ValidationState
        tx = Transaction(nonce=nonce, storage=self.cache_storage, parents=[self._settings.GENESIS_TX1_HASH])
        tx.update_hash()
        tx.init_static_metadata_from_storage(self._settings, self.cache_storage)
        meta = TransactionMetadata(hash=tx.hash)
        meta.validation = ValidationState.FULL
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
            self.assertIn(tx.hash, self.cache_storage.cache_data.dirty_txs)

        # should flush to disk and empty dirty set
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())
        self.assertEqual(0, len(self.cache_storage.cache_data.dirty_txs))

    def test_metadata_only_flush_does_not_serialize_tx(self):
        # Vertex bytes are immutable: they must be serialized and written exactly once (on the first flush after
        # a full save); metadata-only saves must flush only the metadata column family.
        tx = self._get_new_tx(0)
        self.cache_storage.save_transaction(tx)
        self.assertIn(tx.hash, self.cache_storage.cache_data.pending_tx_bytes)

        serialize_spy = Mock(wraps=self.cache_storage._tx_to_bytes)
        self.cache_storage._tx_to_bytes = serialize_spy
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())
        self.assertEqual(1, serialize_spy.call_count)
        self.assertNotIn(tx.hash, self.cache_storage.cache_data.pending_tx_bytes)

        # a metadata-only save flushes the new metadata without re-serializing the vertex
        voided_id = b'x' * 32
        tx.get_metadata().add_voided_by(voided_id)
        self.cache_storage.save_transaction(tx, only_metadata=True)
        self.assertNotIn(tx.hash, self.cache_storage.cache_data.pending_tx_bytes)
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())
        self.assertEqual(1, serialize_spy.call_count)

        # both the metadata update and the vertex bytes are in the database
        tx_from_db = self.cache_storage._get_transaction_from_db(tx.hash)
        self.assertEqual({voided_id}, tx_from_db.get_metadata(use_storage=False).voided_by)
        self.assertEqual(bytes(tx), bytes(tx_from_db))

        # a new full save marks the bytes for (one) rewrite again
        self.cache_storage.save_transaction(tx)
        self.assertIn(tx.hash, self.cache_storage.cache_data.pending_tx_bytes)
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())
        self.assertEqual(2, serialize_spy.call_count)

    def test_metadata_only_eviction_does_not_serialize_tx(self):
        # The cache-eviction write path (_cache_popitem) must also skip vertex bytes for metadata-only updates.
        txs = [self._get_new_tx(nonce) for nonce in range(CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())

        serialize_spy = Mock(wraps=self.cache_storage._tx_to_bytes)
        self.cache_storage._tx_to_bytes = serialize_spy

        # dirty the first tx with a metadata-only save, then evict it by filling the cache
        txs[0].get_metadata().add_voided_by(b'y' * 32)
        self.cache_storage.save_transaction(txs[0], only_metadata=True)
        for nonce in range(CACHE_SIZE, 2 * CACHE_SIZE):
            self.cache_storage.save_transaction(self._get_new_tx(nonce))
        self.assertNotIn(txs[0].hash, self.cache_storage.cache_data.cache)

        # evicting the metadata-dirty tx wrote its metadata but never re-serialized its bytes
        serialized_hashes = {call.args[0].hash for call in serialize_spy.call_args_list}
        self.assertNotIn(txs[0].hash, serialized_hashes)
        tx_from_db = self.cache_storage._get_transaction_from_db(txs[0].hash)
        self.assertEqual({b'y' * 32}, tx_from_db.get_metadata(use_storage=False).voided_by)

    def test_capacity(self):
        # cache should not grow over its capacity
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        self.assertEqual(CACHE_SIZE, len(self.cache_storage.cache_data.cache))

    def test_read_adds_to_cache(self):
        # make sure reading also adds to cache, not only writes
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        # by now, tx[0] will already have left the cache
        self.assertNotIn(txs[0].hash, self.cache_storage.cache_data.cache)

        # read tx
        self.cache_storage.get_transaction(txs[0].hash)

        # now it should be in cache
        self.assertIn(txs[0].hash, self.cache_storage.cache_data.cache)

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
        self.assertIn(txs[0].hash, self.cache_storage.cache_data.cache)

    def test_cache_eviction(self):
        # tests we're evicting the oldest tx from cache
        txs = [self._get_new_tx(nonce) for nonce in range(2 * CACHE_SIZE)]
        for i in range(CACHE_SIZE):
            self.cache_storage.save_transaction(txs[i])

        # next save should evict first tx
        self.cache_storage.save_transaction(txs[CACHE_SIZE])
        self.assertNotIn(txs[0].hash, self.cache_storage.cache_data.cache)
        self.assertIn(txs[CACHE_SIZE].hash, self.cache_storage.cache_data.cache)
        self.assertEqual(CACHE_SIZE, len(self.cache_storage.cache_data.cache))

    def test_flush_thread(self):
        txs = [self._get_new_tx(nonce) for nonce in range(CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        for tx in txs:
            self.assertIn(tx.hash, self.cache_storage.cache_data.dirty_txs)

        # Flush deferred is not None
        self.assertIsNotNone(self.cache_storage.cache_data.flush_deferred)
        last_flush_deferred = self.cache_storage.cache_data.flush_deferred

        # A call when the deferred already exists, shouldn't override it
        self.cache_storage._start_flush_thread()
        self.assertEqual(last_flush_deferred, self.cache_storage.cache_data.flush_deferred)

        # We flush the cache and flush_deferred becomes None
        self.cache_storage._cb_flush_thread(None)
        self.assertIsNone(self.cache_storage.cache_data.flush_deferred)
        # After the interval it becomes not None again
        self.clock.advance(10)
        self.assertIsNotNone(self.cache_storage.cache_data.flush_deferred)

        # If an err occurs, it will become None again and then not None after the interval
        self.cache_storage._err_flush_thread('')
        self.assertIsNone(self.cache_storage.cache_data.flush_deferred)
        self.clock.advance(5)
        self.assertIsNotNone(self.cache_storage.cache_data.flush_deferred)

        # Remove element from cache to test a part of the code
        del self.cache_storage.cache_data.cache[next(iter(self.cache_storage.cache_data.dirty_txs))]
        self.cache_storage._flush_to_storage(self.cache_storage.cache_data.dirty_txs.copy())

    async def test_flush_thread_global_reactor(self) -> None:
        interval = 1
        reactor = get_global_reactor()
        artifacts = self.get_builder() \
            .use_tx_storage_cache(capacity=5) \
            .set_wallet(self._create_test_wallet(unlocked=True)) \
            .set_reactor(reactor) \
            .build()

        self.manager = artifacts.manager
        self.cache_storage = self.manager.tx_storage
        self.cache_storage.cache_data.interval = interval

        og_start_flush_thread = self.cache_storage._start_flush_thread
        og_cb_flush_thread = self.cache_storage._cb_flush_thread
        og_err_flush_thread = self.cache_storage._err_flush_thread

        self.cache_storage._start_flush_thread = Mock(wraps=og_start_flush_thread)
        self.cache_storage._cb_flush_thread = Mock(wraps=og_cb_flush_thread)
        self.cache_storage._err_flush_thread = Mock(wraps=og_err_flush_thread)

        self.manager.start()

        txs = [self._get_new_tx(nonce) for nonce in range(CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        for tx in txs:
            assert tx.hash in self.cache_storage.cache_data.dirty_txs

        assert self.cache_storage.cache_data.flush_deferred is None

        assert self.cache_storage._start_flush_thread.call_count == 0
        assert self.cache_storage._cb_flush_thread.call_count == 0
        assert self.cache_storage._err_flush_thread.call_count == 0

        await deferLater(reactor, interval + 0.1, lambda: None)

        assert self.cache_storage._start_flush_thread.call_count == 1
        assert self.cache_storage._cb_flush_thread.call_count == 1
        assert self.cache_storage._err_flush_thread.call_count == 0

        assert self.cache_storage.cache_data.flush_deferred is None
        self.clean_pending(required_to_quiesce=False)

    def test_topological_sort_dfs(self):
        self.manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT
        add_new_blocks(self.manager, 11, advance_clock=1)
        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]

        total = 0
        for tx in self.cache_storage._run_topological_sort_dfs(root=tx, visited=dict()):
            total += 1
        self.assertEqual(total, 5)
