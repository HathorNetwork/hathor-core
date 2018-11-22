from twisted.internet.task import Clock

from hathor.transaction import Transaction, TransactionMetadata
from hathor.transaction.storage import TransactionMemoryStorage, TransactionCacheStorage

import unittest

CACHE_SIZE = 5


class BasicTransaction(unittest.TestCase):
    def setUp(self):
        store = TransactionMemoryStorage()
        self.reactor = Clock()
        self.cache_storage = TransactionCacheStorage(store, self.reactor, capacity=5)
        self.cache_storage.start()

    def _get_new_tx(self, nonce):
        tx = Transaction(
            nonce=nonce,
            storage=self.cache_storage
        )
        tx.update_hash()
        meta = TransactionMetadata(hash=tx.hash)
        tx._metadata = meta
        return tx

    def test_write_read(self):
        txs = [self._get_new_tx(nonce) for nonce in range(2*CACHE_SIZE)]
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
        txs = [self._get_new_tx(nonce) for nonce in range(2*CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        self.assertEqual(CACHE_SIZE, len(self.cache_storage.cache))

    def test_read_adds_to_cache(self):
        # make sure reading also adds to cache, not only writes
        txs = [self._get_new_tx(nonce) for nonce in range(2*CACHE_SIZE)]
        for tx in txs:
            self.cache_storage.save_transaction(tx)

        # by now, tx[0] will already have left the cache
        self.assertNotIn(txs[0].hash, self.cache_storage.cache)

        # read tx
        self.cache_storage.get_transaction(txs[0].hash)

        # now it should be in cache
        self.assertIn(txs[0].hash, self.cache_storage.cache)


if __name__ == '__main__':
    unittest.main()
