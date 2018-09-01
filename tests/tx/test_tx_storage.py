import unittest
from hathor.transaction.storage import TransactionJSONStorage, TransactionMemoryStorage


class _TransactionStorageTest(unittest.TestCase):

    def setUp(self, tx_storage):
        self.tx_storage = tx_storage
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def test_genesis(self):
        self.assertEqual(1, len(self.genesis_blocks))
        self.assertEqual(2, len(self.genesis_txs))
        self.assertEqual(1, len(self.genesis_blocks[0].outputs))
        for tx in self.genesis:
            tx.verify()

    def test_storage_basic(self):
        self.assertEqual(1, self.tx_storage.count_blocks())

        block_parents_hash = self.tx_storage.get_tip_blocks()
        self.assertEqual(1, len(block_parents_hash))
        self.assertEqual(block_parents_hash[0], self.genesis_blocks[0].hash)


class TransactionJSONStorageTest(_TransactionStorageTest):
    def setUp(self):
        super().setUp(TransactionJSONStorage('/tmp/'))


class TransactionMemoryStorageTest(_TransactionStorageTest):
    def setUp(self):
        super().setUp(TransactionMemoryStorage())
