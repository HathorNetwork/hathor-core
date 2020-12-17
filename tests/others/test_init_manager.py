from typing import Iterator

from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_block, add_new_blocks, add_new_transactions

settings = HathorSettings()


class ModifiedTransactionMemoryStorage(TransactionMemoryStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._first_tx = None

    def set_first_tx(self, tx: BaseTransaction) -> None:
        self._first_tx = tx

    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        skip_hash = None
        if self._first_tx:
            yield self._first_tx
            skip_hash = self._first_tx.hash
        for tx in super().get_all_transactions():
            if tx.hash != skip_hash:
                yield tx


class ManagerInitializationTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tx_storage = ModifiedTransactionMemoryStorage()
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage)

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
        self.tx_storage._reset_cache()
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
        self.tx_storage._reset_cache()
        self.create_peer('testnet', tx_storage=self.tx_storage)
