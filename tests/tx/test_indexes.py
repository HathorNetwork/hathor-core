import pytest

from hathor.crypto.util import decode_address
from hathor.transaction import Transaction
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import HAS_ROCKSDB, add_blocks_unlock_reward, add_new_blocks, gen_new_tx, get_genesis_key


class BaseIndexesTest(unittest.TestCase):
    __test__ = False

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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
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
            {tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter(self.manager.tx_storage)},
            # XXX: what should we expect here? I don't think we should exclude both tx2 and tx3, but maybe let the
            # function using the index decide
            {tx1.hash, tx3.hash}
        )

    def test_genesis_not_in_mempool(self):
        mempool_txs = list(self.tx_storage.indexes.mempool_tips.iter_all(self.tx_storage))
        for tx in self.genesis_txs:
            self.assertNotIn(tx, mempool_txs)

    def _test_confirmed_tx_that_spends_unconfirmed_tx(self, debug=False):
        """
          B ────╮────╮
          A ───vv    v
          C ~~> D -> E

        debug=True is only useful to debug the base and dag setup, it will break the test
        """
        from hathor.transaction import Block, TxInput, TxOutput
        from hathor.transaction.scripts import P2PKH
        from hathor.wallet.base_wallet import WalletOutputInfo

        # ---
        # BEGIN SETUP BASE
        # make some outputs to be spent by A, B and C, and also save some addresses blocks/txs to be used later
        add_new_blocks(self.manager, 5, advance_clock=15)
        block0 = add_blocks_unlock_reward(self.manager)[-1]
        self.wallet.unlock(b'123')
        self.wallet.generate_keys()
        address = list(self.wallet.keys.keys())[0]
        baddress = decode_address(address)
        private_key = self.wallet.get_private_key(address)
        tx0 = self.manager.wallet.prepare_transaction_compute_inputs(
            Transaction,
            [
                WalletOutputInfo(address=baddress, value=10, timelock=None),
                WalletOutputInfo(address=baddress, value=10, timelock=None),
                WalletOutputInfo(address=baddress, value=10, timelock=None),
            ],
            self.manager.tx_storage,
        )
        tx0.weight = 1.0
        tx0.parents = self.manager.get_new_tx_parents()
        tx0.timestamp = int(self.clock.seconds())
        tx0.resolve()
        # XXX: tx0.outputs[0] is always the change output for some reason
        self.assertEqual(len(tx0.outputs), 4)
        self.assertEqual(tx0.outputs[1], tx0.outputs[2])
        self.assertEqual(tx0.outputs[1], tx0.outputs[3])
        self.assertTrue(self.manager.propagate_tx(tx0, False))
        parents0 = [tx0.hash, tx0.parents[0]]
        # END SETUP BASE

        # ---
        # BEGIN SETUP DAG
        # tx_A: ordinary transaction
        self.tx_A = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 1, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_A.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_A.get_sighash_all(), private_key)
        )
        self.tx_A.resolve()
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_A, False))
            self.assertFalse(self.tx_A.get_metadata().voided_by)

        # tx_B: ordinary transaction, not related to tx_A
        self.tx_B = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 2, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_B.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_B.get_sighash_all(), private_key)
        )
        self.tx_B.resolve()
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_B, False))
            self.assertFalse(self.tx_B.get_metadata().voided_by)
            self.assertFalse(self.tx_A.get_metadata().conflict_with)
            self.assertFalse(self.tx_B.get_metadata().conflict_with)

        # tx_C: tip transaction, not related to tx_A or tx_B, must not be the parent of any tx/block
        self.tx_C = Transaction(
            timestamp=(tx0.timestamp + 1),
            weight=1.0,
            inputs=[TxInput(tx0.hash, 3, b'')],
            outputs=[TxOutput(10, P2PKH.create_output_script(baddress))],
            parents=list(parents0),
            storage=self.tx_storage,
        )
        self.tx_C.inputs[0].data = P2PKH.create_input_data(
            *self.wallet.get_input_aux_data(self.tx_C.get_sighash_all(), private_key)
        )
        self.tx_C.resolve()
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_C, False))
            self.assertFalse(self.tx_C.get_metadata().voided_by)
            self.assertFalse(self.tx_A.get_metadata().conflict_with)
            self.assertFalse(self.tx_B.get_metadata().conflict_with)
            self.assertFalse(self.tx_C.get_metadata().conflict_with)

        # tx_D: has tx_A and tx_B as parents, but spends from tx_C, confirmed by block_E
        self.tx_D = Transaction(
            timestamp=(self.tx_A.timestamp + 1),
            weight=1.0,
            inputs=[
                TxInput(self.tx_A.hash, 0, b''),
                TxInput(self.tx_B.hash, 0, b''),
                TxInput(self.tx_C.hash, 0, b''),
            ],
            outputs=[TxOutput(30, P2PKH.create_output_script(baddress))],
            parents=[self.tx_A.hash, self.tx_B.hash],
            storage=self.tx_storage,
        )
        for i in range(3):
            self.tx_D.inputs[i].data = P2PKH.create_input_data(
                *self.wallet.get_input_aux_data(self.tx_D.get_sighash_all(), private_key)
            )
        self.tx_D.resolve()
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.tx_D, False))
            self.assertFalse(self.tx_D.get_metadata().voided_by)

        # block_E: has tx_D as parent (and also tx_A, to fill it up, but MUST NOT confirm tx_C
        self.block_E = Block(
            timestamp=(self.tx_D.timestamp + 1),
            outputs=[TxOutput(6400, P2PKH.create_output_script(baddress))],
            parents=[block0.hash, self.tx_D.hash, self.tx_B.hash],
            weight=1.0,
            storage=self.tx_storage,
        )
        self.block_E.resolve()
        if debug:
            self.assertTrue(self.manager.propagate_tx(self.block_E, False))
            self.assertFalse(self.block_E.get_metadata().voided_by)
            tips = [x.data for x in self.tx_storage.get_all_tips()]
            self.assertEqual(set(tips), {self.tx_C.hash, self.block_E.hash})
        # END SETUP DAG

        # ---
        # BEGIN TEST INDEX BEHAVIOR
        # order of operations to simulate what will happen on sync-v2 and what we want to avoid:
        deps_index = self.manager.tx_storage.indexes.deps

        # - add block_E to deps-index, it should then say tx_D and tx_B are needed
        self.assertFalse(self.block_E.get_metadata().validation.is_fully_connected())
        deps_index.add_tx(self.block_E)
        self.assertEqual(
            set(deps_index._iter_needed_txs()),
            {self.tx_D.hash, self.tx_B.hash},
        )

        # - add tx_D to deps-index, it should now say tx_A, tx_B and most importantly tx_C are needed
        self.assertFalse(self.tx_D.get_metadata().validation.is_fully_connected())
        deps_index.add_tx(self.tx_D)
        deps_index.remove_from_needed_index(self.tx_D.hash)
        # XXX: the next assert will fail when the index does not use tx.get_all_dependencies()
        self.assertEqual(
            set(deps_index._iter_needed_txs()),
            {self.tx_A.hash, self.tx_B.hash, self.tx_C.hash},
        )
        # END TEST INDEX BEHAVIOR


class BaseMemoryIndexesTest(BaseIndexesTest):
    def setUp(self):
        from hathor.transaction.storage import TransactionMemoryStorage

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

    def test_deps_index(self):
        from hathor.indexes.memory_deps_index import MemoryDepsIndex

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        # XXX: this test makes use of the internals of the memory deps-index implementation
        deps_index: MemoryDepsIndex = self.manager.tx_storage.indexes.deps

        address = self.get_address(0)
        value = 500
        tx = gen_new_tx(self.manager, address, value)

        # call add_tx the first time
        deps_index.add_tx(tx)

        # snapshot of state before
        rev_dep_index = deps_index._rev_dep_index.copy()
        txs_with_deps_ready = deps_index._txs_with_deps_ready.copy()
        needed_txs_index = deps_index._needed_txs_index.copy()

        # call add_tx the second time
        deps_index.add_tx(tx)

        # state must not have changed
        self.assertEqual(rev_dep_index, deps_index._rev_dep_index)
        self.assertEqual(txs_with_deps_ready, deps_index._txs_with_deps_ready)
        self.assertEqual(needed_txs_index, deps_index._needed_txs_index)

    def test_confirmed_tx_that_spends_unconfirmed_tx(self):
        self._test_confirmed_tx_that_spends_unconfirmed_tx()


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBIndexesTest(BaseIndexesTest):
    def setUp(self):
        import tempfile

        from hathor.transaction.storage import TransactionRocksDBStorage

        super().setUp()
        self.wallet = Wallet()
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        self.tx_storage = TransactionRocksDBStorage(directory)
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

    def test_deps_index(self):
        from hathor.indexes.rocksdb_deps_index import RocksDBDepsIndex

        indexes = self.manager.tx_storage.indexes
        deps_index = indexes.deps = RocksDBDepsIndex(indexes._db, _force=True)

        add_new_blocks(self.manager, 5, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

        # XXX: this test makes use of the internals of the rocksdb deps-index implementation
        deps_index: RocksDBDepsIndex = self.manager.tx_storage.indexes.deps

        address = self.get_address(0)
        value = 500
        tx = gen_new_tx(self.manager, address, value)

        # call add_tx the first time
        deps_index.add_tx(tx)

        # snapshot of state before
        db_dict_before = deps_index._clone_into_dict()

        # call add_tx the second time
        deps_index.add_tx(tx)

        # state must not have changed
        db_dict_after = deps_index._clone_into_dict()
        self.assertEqual(db_dict_before, db_dict_after)

    def test_confirmed_tx_that_spends_unconfirmed_tx(self):
        from hathor.indexes.rocksdb_deps_index import RocksDBDepsIndex

        indexes = self.manager.tx_storage.indexes
        indexes.deps = RocksDBDepsIndex(indexes._db, _force=True)
        self._test_confirmed_tx_that_spends_unconfirmed_tx()


class SyncV1MemoryIndexesTest(unittest.SyncV1Params, BaseMemoryIndexesTest):
    __test__ = True


class SyncV2MemoryIndexesTest(unittest.SyncV2Params, BaseMemoryIndexesTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeMemoryIndexesTest(unittest.SyncBridgeParams, SyncV2MemoryIndexesTest):
    pass


class SyncV1RocksDBIndexesTest(unittest.SyncV1Params, BaseRocksDBIndexesTest):
    __test__ = True


class SyncV2RocksDBIndexesTest(unittest.SyncV2Params, BaseRocksDBIndexesTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeRocksDBIndexesTest(unittest.SyncBridgeParams, SyncV2RocksDBIndexesTest):
    pass
