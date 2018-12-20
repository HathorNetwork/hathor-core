import time

from twisted.internet.task import Clock

from tests import unittest
from tests.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet.base_wallet import WalletOutputInfo


class MemoryNotSharedTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.clock = Clock()
        self.clock.advance(time.time())
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

    def test_memory_not_shared(self):
        from itertools import chain
        tips = chain(self.tx_storage.get_block_tips(), self.tx_storage.get_tx_tips())

        for interval in tips:
            tx1 = self.tx_storage.get_transaction(interval.data)
            tx2 = self.tx_storage.get_transaction(interval.data)

            # just making sure, if it is genesis the test is wrong
            self.assertFalse(tx1.is_genesis)

            # naturally they should be equal, but not the same object
            self.assertTrue(tx1 == tx2)
            self.assertFalse(tx1 is tx2)

            meta1 = tx1.get_metadata()
            meta2 = tx2.get_metadata()

            # neither the metadata
            self.assertTrue(meta1 == meta2)
            self.assertFalse(meta1 is meta2)


class MemoryIsharedTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.clock = Clock()
        self.clock.advance(time.time())
        self.network = 'testnet'
        self.tx_storage = TransactionMemoryStorage(_clone_if_needed=False)
        self.manager = self.create_peer(self.network, unlock_wallet=True, tx_storage=self.tx_storage)

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

    def test_memory_not_shared(self):
        from itertools import chain
        tx_storage = self.manager.tx_storage
        tips = chain(tx_storage.get_block_tips(), tx_storage.get_tx_tips())

        for interval in tips:
            tx1 = self.tx_storage.get_transaction(interval.data)
            tx2 = self.tx_storage.get_transaction(interval.data)

            # just making sure, if it is genesis the test is wrong
            self.assertFalse(tx1.is_genesis)

            # naturally they should be equal, but this time so do the objects
            self.assertTrue(tx1 == tx2)
            self.assertTrue(tx1 is tx2)

            meta1 = tx1.get_metadata()
            meta2 = tx2.get_metadata()

            # and naturally the metadata too
            self.assertTrue(meta1 == meta2)
            self.assertTrue(meta1 is meta2)
