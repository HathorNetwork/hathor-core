from hathor.crypto.util import decode_address
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletOutputInfo
from tests import unittest
from tests.utils import add_new_blocks


class TwinTransactionTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True, wallet_index=True)

    def test_twin_tx(self):
        add_new_blocks(self.manager, 5, advance_clock=15)

        address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        value1 = 100
        value2 = 101

        outputs = [
            WalletOutputInfo(address=decode_address(address), value=int(value1), timelock=None),
            WalletOutputInfo(address=decode_address(address), value=int(value2), timelock=None)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()

        # Change of parents only, so it's a twin
        tx2 = Transaction.create_from_struct(tx1.get_struct())
        tx2.parents = [tx1.parents[1], tx1.parents[0]]
        tx2.resolve()
        self.assertNotEqual(tx1.hash, tx2.hash)

        self.manager.propagate_tx(tx1)
        self.run_to_completion()

        wallet_data = self.manager.tx_storage.wallet_index.get_from_address(address)
        self.assertEqual(len(wallet_data), 2)
        self.assertTrue(wallet_data[0].is_output)
        self.assertEqual(wallet_data[0].tx_id, tx1.hash_hex)
        self.assertEqual(wallet_data[0].index, 1)
        self.assertEqual(wallet_data[0].value, value1)
        self.assertEqual(wallet_data[0].timestamp, tx1.timestamp)
        self.assertEqual(wallet_data[0].timelock, None)
        self.assertFalse(wallet_data[0].voided)

        self.assertTrue(wallet_data[1].is_output)
        self.assertEqual(wallet_data[1].tx_id, tx1.hash_hex)
        self.assertEqual(wallet_data[1].index, 2)
        self.assertEqual(wallet_data[1].value, value2)
        self.assertEqual(wallet_data[1].timestamp, tx1.timestamp)
        self.assertEqual(wallet_data[1].timelock, None)
        self.assertFalse(wallet_data[1].voided)

        # Propagate a conflicting twin transaction
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        wallet_data = self.manager.tx_storage.wallet_index.get_from_address(address)
        self.assertEqual(len(wallet_data), 4)
        self.assertTrue(wallet_data[0].is_output)
        self.assertEqual(wallet_data[0].tx_id, tx1.hash_hex)
        self.assertEqual(wallet_data[0].index, 1)
        self.assertEqual(wallet_data[0].value, value1)
        self.assertEqual(wallet_data[0].timestamp, tx1.timestamp)
        self.assertEqual(wallet_data[0].timelock, None)
        self.assertTrue(wallet_data[0].voided)

        self.assertTrue(wallet_data[1].is_output)
        self.assertEqual(wallet_data[1].tx_id, tx1.hash_hex)
        self.assertEqual(wallet_data[1].index, 2)
        self.assertEqual(wallet_data[1].value, value2)
        self.assertEqual(wallet_data[1].timestamp, tx1.timestamp)
        self.assertEqual(wallet_data[1].timelock, None)
        self.assertTrue(wallet_data[1].voided)
