from twisted.internet.task import Clock

from tests import unittest
from tests.utils import add_new_blocks

from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletOutputInfo, UnspentTx, SpentTx, WalletBalance

import time


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)
        self.tx_storage = self.manager.tx_storage

        add_new_blocks(self.manager, 3, advance_clock=15)

        address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        value = 100

        outputs = [
            WalletOutputInfo(address=self.manager.wallet.decode_address(address), value=int(value), timelock=None)
        ]

        self.tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        self.tx1.weight = 10
        self.tx1.parents = self.manager.get_new_tx_parents()
        self.tx1.timestamp = int(self.clock.seconds())
        self.tx1.resolve()
        self.manager.propagate_tx(self.tx1)

    def tearDown(self):
        super().tearDown()
        self.manager.stop()
        # self.manager.stop()

    def test_validator_simple(self):
        # Tx2 is twin with tx1 but less acc weight, so it will get voided

        # Start balance
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Change of parents only, so it's a twin.
        # With less weight, so the balance will continue because tx1 will be the winner
        tx2 = Transaction.create_from_struct(self.tx1.get_struct(), storage=self.tx_storage)
        tx2.parents = [self.tx1.parents[1], self.tx1.parents[0]]
        tx2.weight = 9
        tx2.resolve()

        # Propagate a conflicting twin transaction
        self.assertTrue(self.manager.propagate_tx(tx2))

        meta1 = self.tx1.get_metadata(force_reload=True)
        self.assertEqual(meta1.twins, {tx2.hash})

        meta2 = tx2.get_metadata(force_reload=True)
        self.assertEqual(meta2.voided_by, {tx2.hash})

        # Balance is the same
        self.assertEqual(self.manager.wallet.balance, WalletBalance(0, 5900))

        # Voided wallet history
        index_voided = 0
        output_voided = tx2.outputs[index_voided]
        voided_unspent = UnspentTx(tx2.hash, index_voided, output_voided.value, tx2.timestamp, voided=True)
        address = output_voided.to_human_readable()['address']
        self.assertEqual(len(self.manager.wallet.voided_unspent), 1)
        self.assertEqual(len(self.manager.wallet.voided_unspent[address]), 1)
        self.assertEqual(self.manager.wallet.voided_unspent[address][0].to_dict(), voided_unspent.to_dict())

        input_voided = tx2.inputs[0]
        key = (input_voided.tx_id, input_voided.index)
        voided_spent = SpentTx(tx2.hash, input_voided.tx_id, input_voided.index, 2000, tx2.timestamp, voided=True)
        self.assertEqual(len(self.manager.wallet.voided_spent), 1)
        self.assertEqual(len(self.manager.wallet.voided_spent[key]), 1)
        self.assertEqual(self.manager.wallet.voided_spent[key][0].to_dict(), voided_spent.to_dict())


if __name__ == '__main__':
    unittest.main()
