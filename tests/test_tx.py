import unittest
from hathor.transaction import Transaction, Output, Input
from hathor.storage import TransactionJSONStorage


class BasicTransactionAndStorageTest(unittest.TestCase):
    def test_transaction_and_storage(self):
        # create new transaction
        tx_orig = Transaction(outputs=[Output(b'foo', 1)])
        # resolve hash (mine)
        tx_orig.resolve()

        # save transaction
        storage = TransactionJSONStorage()
        storage.save_transaction(tx_orig)

        # retrieve saved transaction
        tx_read = storage.get_transaction_by_hash(tx_orig.hash)

        # should be identical
        # XXX: maybe Transaction could implement __eq__
        self.assertEqual(storage.serialize(tx_orig), storage.serialize(tx_read))


if __name__ == '__main__':
    unittest.main()
