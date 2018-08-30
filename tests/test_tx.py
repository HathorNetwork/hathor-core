import unittest
from hathor.transaction.transaction import Transaction
from hathor.transaction.base_transaction import Input, Output
from hathor.storage.json_storage import TransactionJSONStorage


class BasicTransactionAndStorageTest(unittest.TestCase):
    def test_transaction_and_storage(self):
        # create new transaction

        # only input is a fake block
        tx_id = bytes.fromhex('24042b5a5ea5f9cf1889bcae9291b68162eda656e8a440363861b5a74efdaec2')
        index = 1
        # TODO for now just use any bytes as data.
        # When we start validating output script and input data, we shoudl change
        data = tx_id
        inputs = []
        inputs.append(Input(tx_id, index, data))

        # output
        # TODO for now just use any bytes as script.
        # When we start validating output script and input data, we shoudl change
        script = bytes.fromhex('24042b5a5ea5f9cf1889bcae9291b68162eda656e8a440363861b5a74efdaec2')
        value = 4
        outputs = []
        outputs.append(Output(value, script))

        tx1 = Transaction(
            inputs=inputs,
            outputs=outputs,
        )
        # calculate nonce and hash
        tx1.resolve()

        # save transaction
        storage = TransactionJSONStorage(path='/tmp/')
        storage.save_transaction(tx1)

        # retrieve saved transaction
        tx1_read = storage.get_transaction_by_hash_bytes(tx1.hash)

        # should be identical
        # XXX: maybe Transaction could implement __eq__
        self.assertEqual(tx1, tx1_read)


if __name__ == '__main__':
    unittest.main()
