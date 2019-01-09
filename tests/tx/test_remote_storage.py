from tests import unittest
from tests.utils import start_remote_storage, add_new_blocks, add_new_transactions
from twisted.internet.task import Clock

from hathor.transaction.storage.remote_storage import RemoteCommunicationError
from hathor.transaction import Transaction, Block
from hathor.transaction.base_transaction import tx_or_block_from_proto

import time
import datetime


class RemoteStorageTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        tx_storage, self._server = start_remote_storage()

        self.clock = Clock()
        self.clock.advance(time.time())
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)
        self.manager.tx_storage = tx_storage

        self.genesis = tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def tearDown(self):
        self._server.stop(0).wait()

    def test_exceptions(self):
        self._server.stop(0).wait()

        with self.assertRaises(RemoteCommunicationError):
            self.manager.tx_storage.get_block_count()

    def test_get_txs(self):
        first_block = add_new_blocks(self.manager, 3, advance_clock=1)[0]
        first_tx = add_new_transactions(self.manager, 3, advance_clock=1)[0]

        # Using timestamp as float to test code
        txs, _ = self.manager.tx_storage.get_older_txs_after(float(first_tx.timestamp), first_tx.hash, 3)
        self.assertEqual(len(txs), 2)

        txs, _ = self.manager.tx_storage.get_newer_txs_after(float(first_tx.timestamp), first_tx.hash, 3)
        self.assertEqual(len(txs), 2)

        blocks, _ = self.manager.tx_storage.get_older_blocks_after(float(first_block.timestamp), first_block.hash, 3)
        self.assertEqual(len(blocks), 1)

        blocks, _ = self.manager.tx_storage.get_newer_blocks_after(float(first_block.timestamp), first_block.hash, 3)
        self.assertEqual(len(blocks), 2)

        tx = txs[0]
        proto = tx.to_proto(include_metadata=False)
        tx2 = Transaction.create_from_proto(proto)
        self.assertEqual(tx, tx2)

        block = blocks[0]
        proto2 = block.to_proto(include_metadata=False)
        block2 = Block.create_from_proto(proto2)
        self.assertEqual(block, block2)

        tx3 = tx_or_block_from_proto(proto)
        self.assertEqual(tx, tx3)

        proto.ClearField('transaction')

        with self.assertRaises(ValueError):
            tx_or_block_from_proto(proto)

        t = datetime.datetime.now() - datetime.timedelta(seconds=1)
        t_tx = tx.get_time_from_now()
        t2_tx = tx.get_time_from_now(now=t)

        self.assertNotEqual(t_tx, t2_tx)
