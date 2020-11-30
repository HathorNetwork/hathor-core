from hathor.crypto.util import decode_address
from hathor.transaction import Transaction
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, get_genesis_key


class BasicTransaction(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = Wallet()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True)
        blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = blocks[-1]

    def test_tx_tips_with_conflict(self):
        from hathor.wallet.base_wallet import WalletOutputInfo

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address = self.get_address(0)
        value = 500

        outputs = [WalletOutputInfo(address=decode_address(address), value=value, timelock=None)]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 2.0
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()
        self.assertTrue(self.manager.propagate_tx(tx1, False))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            {tx1.hash}
        )

        outputs = [WalletOutputInfo(address=decode_address(address), value=value, timelock=None)]

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx2.weight = 2.0
        tx2.parents = [tx1.hash] + self.manager.get_new_tx_parents()[1:]
        self.assertIn(tx1.hash, tx2.parents)
        tx2.timestamp = int(self.clock.seconds()) + 1
        tx2.resolve()
        self.assertTrue(self.manager.propagate_tx(tx2, False))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            {tx2.hash}
        )

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.timestamp = tx2.timestamp + 1
        self.assertIn(tx1.hash, tx3.parents)
        tx3.resolve()
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3, False))
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
            # function using the index decide
            # {tx1.hash, tx3.hash}
            {tx1.hash}
        )

    def test_tx_tips_voided(self):
        from hathor.wallet.base_wallet import WalletOutputInfo

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        address1 = self.get_address(0)
        address2 = self.get_address(1)
        address3 = self.get_address(2)
        output1 = WalletOutputInfo(address=decode_address(address1), value=123, timelock=None)
        output2 = WalletOutputInfo(address=decode_address(address2), value=234, timelock=None)
        output3 = WalletOutputInfo(address=decode_address(address3), value=345, timelock=None)
        outputs = [output1, output2, output3]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 2.0
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        tx1.resolve()
        self.assertTrue(self.manager.propagate_tx(tx1, False))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            {tx1.hash}
        )

        tx2 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx2.weight = 2.0
        tx2.parents = [tx1.hash] + self.manager.get_new_tx_parents()[1:]
        self.assertIn(tx1.hash, tx2.parents)
        tx2.timestamp = int(self.clock.seconds()) + 1
        tx2.resolve()
        self.assertTrue(self.manager.propagate_tx(tx2, False))
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            {tx2.hash}
        )

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.weight = 3.0
        # tx3.timestamp = tx2.timestamp + 1
        tx3.parents = tx1.parents
        # self.assertIn(tx1.hash, tx3.parents)
        tx3.resolve()
        self.assertNotEqual(tx2.hash, tx3.hash)
        self.assertTrue(self.manager.propagate_tx(tx3, False))
        # self.assertIn(tx3.hash, tx2.get_metadata().voided_by)
        self.assertIn(tx3.hash, tx2.get_metadata().conflict_with)
        self.assertEqual(
            {tx.hash for tx in self.manager.tx_storage.iter_tx_tips()},
            # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
            # function using the index decide
            {tx1.hash, tx3.hash}
        )


if __name__ == '__main__':
    unittest.main()
