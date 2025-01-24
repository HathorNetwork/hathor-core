from typing import Iterator

from hathor.pubsub import PubSubManager
from hathor.simulator.utils import add_new_block, add_new_blocks
from hathor.transaction import BaseTransaction
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest
from tests.unittest import TestBuilder
from tests.utils import add_blocks_unlock_reward, add_new_double_spending, add_new_transactions


class ModifiedTransactionMemoryStorage(TransactionMemoryStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._first_tx = None

    def set_first_tx(self, tx: BaseTransaction) -> None:
        self._first_tx = tx

    def _get_all_transactions(self) -> Iterator[BaseTransaction]:
        skip_hash = None
        if self._first_tx:
            yield self._first_tx
            skip_hash = self._first_tx.hash
        for tx in super()._get_all_transactions():
            if tx.hash != skip_hash:
                yield tx


class SimpleManagerInitializationTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tx_storage = ModifiedTransactionMemoryStorage(settings=self._settings)
        self.pubsub = PubSubManager(self.clock)

    def test_invalid_arguments(self):
        # this is a base case, it shouldn't raise any error
        # (otherwise we might not be testing the correct thing below)
        builder = TestBuilder()
        builder.set_tx_storage(self.tx_storage)
        artifacts = builder.build()
        manager = artifacts.manager
        del manager

        builder = TestBuilder()
        builder.set_tx_storage(self.tx_storage)

        # removed method
        with self.assertRaises(AttributeError):
            builder.disable_sync_v1()

        # but also it should still be impossible to build with no sync
        builder.disable_sync_v2()
        with self.assertRaises(TypeError):
            builder.build()

    def tests_init_with_stratum(self):
        builder = TestBuilder()
        builder.set_tx_storage(self.tx_storage)
        builder.enable_stratum_server()
        artifacts = builder.build()
        manager = artifacts.manager
        manager.start()
        manager.stop()
        del manager

    def test_double_start(self):
        builder = TestBuilder()
        builder.set_tx_storage(self.tx_storage)
        artifacts = builder.build()
        manager = artifacts.manager
        manager.start()
        with self.assertRaises(Exception):
            manager.start()

    def test_wrong_stop(self):
        builder = TestBuilder()
        builder.set_tx_storage(self.tx_storage)
        artifacts = builder.build()
        manager = artifacts.manager
        with self.assertRaises(Exception):
            manager.stop()
        manager.start()
        manager.stop()
        with self.assertRaises(Exception):
            manager.stop()


class ManagerInitializationTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tx_storage = ModifiedTransactionMemoryStorage(settings=self._settings)
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, tx_storage=self.tx_storage)

        self.all_hashes = set()
        for tx in self.manager.tx_storage.get_all_transactions():
            self.all_hashes.add(tx.hash)

        # generate blocks and transactions where blk1 is spent by tx1
        self.blk1 = add_new_block(self.manager, advance_clock=15)
        self.block_list = add_blocks_unlock_reward(self.manager)

        self.tx_list = add_new_transactions(self.manager, 5, advance_clock=15)
        self.tx1 = self.tx_list[0]
        self.assertTrue(self.tx1.inputs[0].tx_id == self.blk1.hash)

        self.block_list2 = add_new_blocks(self.manager, 8, advance_clock=15)

        # collect all hashes
        self.all_hashes.add(self.blk1.hash)
        self.all_hashes.update(x.hash for x in self.block_list)
        self.all_hashes.update(x.hash for x in self.tx_list)
        self.all_hashes.update(x.hash for x in self.block_list2)

    def test_init_good_order(self):
        """We force the first element of `get_all_transactions` to be the block
        we need to ensure tx1 is valid.
        """
        self.tx_storage.set_first_tx(self.block_list[-1])

        # check that get_all_transactions is working properly
        seen = set()
        for tx in self.tx_storage.get_all_transactions():
            if tx.hash == self.tx1.hash:
                self.assertIn(self.block_list[-1].hash, seen)
            seen.add(tx.hash)
        self.assertEqual(seen, self.all_hashes)

        # a new manager must be successfully initialized
        self.tx_storage.reset_indexes()
        self.create_peer('testnet', tx_storage=self.tx_storage)

    def test_init_unfavorable_order(self):
        """We force the first element of `get_all_transactions` to be a transaction
        that has tx1 as parent. So, tx1 would raise RewardLocked exception if
        topological sort hasn't handled it.
        """
        self.tx_storage.set_first_tx(self.tx1)

        # check that get_all_transactions is working properly
        seen = set()
        for tx in self.tx_storage.get_all_transactions():
            if tx.hash == self.tx1.hash:
                self.assertNotIn(self.block_list[-1].hash, seen)
            seen.add(tx.hash)
        self.assertEqual(seen, self.all_hashes)

        # a new manager must be successfully initialized
        self.tx_storage.reset_indexes()
        self.create_peer('testnet', tx_storage=self.tx_storage)

    def test_init_not_voided_tips(self):
        # add a bunch of blocks and transactions
        for i in range(30):
            add_new_block(self.manager, advance_clock=15)
            add_new_transactions(self.manager, 5, advance_clock=15)

        # add a bunch of conflicting transactions, these will all become voided
        for i in range(50):
            add_new_double_spending(self.manager)

        # finish up with another bunch of blocks and transactions
        for i in range(30):
            add_new_block(self.manager, advance_clock=15)
            add_new_transactions(self.manager, 5, advance_clock=15)

        # not the point of this test, but just a sanity check
        self.assertConsensusValid(self.manager)

        # make sure we have the right number of voided transactions
        self.assertEqual(50, sum(bool(tx.get_metadata().voided_by) for tx in self.tx_storage.get_all_transactions()))

        # create a new manager (which will initialize in the self.create_peer call)
        self.tx_storage.reset_indexes()
        self.manager.stop()
        manager = self.create_peer(self.network, tx_storage=self.tx_storage, full_verification=False)

        # make sure none of its tx tips are voided
        for tx in manager.tx_storage.iter_mempool_tips():
            self.assertFalse(tx.get_metadata().voided_by, tx.hash_hex)
