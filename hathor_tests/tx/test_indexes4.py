from hathor.crypto.util import decode_address
from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletOutputInfo
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class SimulatorIndexesTestCase(unittest.TestCase):
    def _build_randomized_blockchain(self, *, utxo_index=False):
        tx_storage = self.create_tx_storage()
        manager = self.create_peer('testnet', tx_storage=tx_storage, unlock_wallet=True, wallet_index=True,
                                   utxo_index=utxo_index)

        add_new_blocks(manager, 50, advance_clock=15)

        add_blocks_unlock_reward(manager)
        address1 = self.get_address(0)
        address2 = self.get_address(1)
        address3 = self.get_address(2)
        output1 = WalletOutputInfo(address=decode_address(address1), value=123, timelock=None)
        output2 = WalletOutputInfo(address=decode_address(address2), value=234, timelock=None)
        output3 = WalletOutputInfo(address=decode_address(address3), value=345, timelock=None)
        outputs = [output1, output2, output3]

        tx1 = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
        tx1.weight = 2.0
        tx1.parents = manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        manager.cpu_mining_service.resolve(tx1)
        assert manager.propagate_tx(tx1)

        tx2 = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
        tx2.weight = 2.0
        tx2.parents = [tx1.hash] + manager.get_new_tx_parents()[1:]
        self.assertIn(tx1.hash, tx2.parents)
        tx2.timestamp = int(self.clock.seconds()) + 1
        manager.cpu_mining_service.resolve(tx2)
        assert manager.propagate_tx(tx2)

        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.weight = 3.0
        tx3.parents = tx1.parents
        manager.cpu_mining_service.resolve(tx3)
        assert manager.propagate_tx(tx3)

        for _ in range(100):
            address = self.get_address(0)
            value = 500
            tx = gen_new_tx(manager, address, value)
            assert manager.propagate_tx(tx)
        return manager

    def test_index_initialization(self):
        self.manager = self._build_randomized_blockchain(utxo_index=True)

        # XXX: this test makes use of the internals of TipsIndex, AddressIndex and UtxoIndex
        tx_storage = self.manager.tx_storage

        # XXX: sanity check that we've at least produced something
        self.assertGreater(tx_storage.get_vertices_count(), 3)

        for tx in tx_storage.get_all_transactions():
            if tx.is_transaction and tx.get_metadata().voided_by:
                break
        else:
            raise AssertionError('no voided tx found')

        # base tips indexes
        base_address_index = list(tx_storage.indexes.addresses.get_all_internal())
        base_utxo_index = list(tx_storage.indexes.utxo.get_all_internal())

        # reset the indexes and force a re-initialization of all indexes
        tx_storage._manually_initialize()
        tx_storage.indexes.enable_address_index(self.manager.pubsub)
        tx_storage._manually_initialize_indexes()

        reinit_address_index = list(tx_storage.indexes.addresses.get_all_internal())
        reinit_utxo_index = list(tx_storage.indexes.utxo.get_all_internal())

        self.assertEqual(reinit_address_index, base_address_index)
        self.assertEqual(reinit_utxo_index, base_utxo_index)

        # reset again
        tx_storage._manually_initialize()
        tx_storage.indexes.enable_address_index(self.manager.pubsub)
        tx_storage._manually_initialize_indexes()

        newinit_address_index = list(tx_storage.indexes.addresses.get_all_internal())
        newinit_utxo_index = list(tx_storage.indexes.utxo.get_all_internal())

        self.assertEqual(newinit_address_index, base_address_index)
        self.assertEqual(newinit_utxo_index, base_utxo_index)

    def test_topological_iterators(self):
        self.manager = self._build_randomized_blockchain()
        tx_storage = self.manager.tx_storage

        # XXX: sanity check that we've at least produced something
        total_count = tx_storage.get_vertices_count()
        self.assertGreater(total_count, 3)

        # XXX: sanity check that the children metadata is properly set (this is needed for one of the iterators)
        for tx in tx_storage.get_all_transactions():
            for parent_tx in map(tx_storage.get_transaction, tx.parents):
                self.assertIn(tx.hash, parent_tx.get_children())

        # test iterators, name is used to aid in assert messages
        iterators = [
            ('dfs', tx_storage._topological_sort_dfs()),
            ('timestamp_index', tx_storage._topological_sort_timestamp_index()),
            ('metadata', tx_storage._topological_sort_metadata()),
        ]
        for name, it in iterators:
            # collect all transactions, while checking that inputs/parents are consistent
            txs = list(it)
            # must be complete
            self.assertEqual(len(txs), total_count, f'iterator "{name}" does not cover all txs')
            # must be topological
            self.assertIsTopological(iter(txs), f'iterator "{name}" is not topological')
