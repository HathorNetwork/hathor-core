from hathor.simulator import FakeConnection
from tests import unittest
from tests.simulation.base import SimulatorTestCase


class BaseSimulatorIndexesTestCase(SimulatorTestCase):
    def _build_randomized_blockchain(self):
        manager = self.create_peer()

        # FIXME: this second peer is only needed because of some problem on the simulator
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager, manager2, latency=0.150)
        self.simulator.add_connection(conn12)
        self.simulator.run(10)

        miner1 = self.simulator.create_miner(manager, hashpower=100e6)
        miner1.start()
        self.simulator.run(10)

        miner2 = self.simulator.create_miner(manager, hashpower=100e6)
        miner2.start()
        self.simulator.run(10)

        gen_tx1 = self.simulator.create_tx_generator(manager, rate=2 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(10)

        gen_tx2 = self.simulator.create_tx_generator(manager, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()
        self.simulator.run(10 * 60)

        miner1.stop()
        miner2.stop()
        gen_tx1.stop()
        gen_tx2.stop()

        self.simulator.run(5 * 60)
        return manager

    def test_tips_index_initialization(self):
        from intervaltree import IntervalTree

        # XXX: this test makes use of the internals of TipsIndex
        manager = self._build_randomized_blockchain()
        tx_storage = manager.tx_storage
        assert tx_storage.indexes is not None

        # XXX: sanity check that we've at least produced something
        self.assertGreater(tx_storage.get_count_tx_blocks(), 3)

        # base tips indexes
        base_all_tips_tree = tx_storage.indexes.all_tips.tree.copy()
        base_block_tips_tree = tx_storage.indexes.block_tips.tree.copy()
        base_tx_tips_tree = tx_storage.indexes.tx_tips.tree.copy()

        # reset the indexes and force a manual initialization
        tx_storage._reset_cache()
        manager._initialize_components()

        reinit_all_tips_tree = tx_storage.indexes.all_tips.tree.copy()
        reinit_block_tips_tree = tx_storage.indexes.block_tips.tree.copy()
        reinit_tx_tips_tree = tx_storage.indexes.tx_tips.tree.copy()

        self.assertEqual(reinit_all_tips_tree, base_all_tips_tree)
        self.assertEqual(reinit_block_tips_tree, base_block_tips_tree)
        self.assertEqual(reinit_tx_tips_tree, base_tx_tips_tree)

        # reset again but now initilize from the new function
        # XXX: manually reset each index, because we're using MemoryTimestampIndex and we need that for the new init
        for tip_index in [tx_storage.indexes.all_tips, tx_storage.indexes.block_tips, tx_storage.indexes.tx_tips]:
            tip_index.tx_last_interval = {}
            tip_index.tree = IntervalTree()
        tx_storage.indexes._manually_initialize_tips_indexes(tx_storage)

        newinit_all_tips_tree = tx_storage.indexes.all_tips.tree.copy()
        newinit_block_tips_tree = tx_storage.indexes.block_tips.tree.copy()
        newinit_tx_tips_tree = tx_storage.indexes.tx_tips.tree.copy()

        self.assertEqual(newinit_all_tips_tree, base_all_tips_tree)
        self.assertEqual(newinit_block_tips_tree, base_block_tips_tree)
        self.assertEqual(newinit_tx_tips_tree, base_tx_tips_tree)

    def test_topological_iterators(self):
        manager = self._build_randomized_blockchain()
        tx_storage = manager.tx_storage

        # XXX: sanity check that we've at least produced something
        self.assertGreater(tx_storage.get_count_tx_blocks(), 3)

        # test iterators, name is used to aid in assert messages
        iterators = [
            ('traditional', tx_storage._topological_sort()),
            ('fast', tx_storage._topological_fast()),
        ]
        for name, it in iterators:
            # collect all transactions
            txs = list(it)
            # must be complete
            self.assertEqual(len(txs), tx_storage.get_count_tx_blocks(),
                             f'iterator "{name}" does not cover all txs')
            # must be topological
            self.assertIsTopological(iter(txs),
                                     f'iterator "{name}" is not topological')


class SyncV1SimulatorIndexesTestCase(unittest.SyncV1Params, BaseSimulatorIndexesTestCase):
    __test__ = True


class SyncV2SimulatorIndexesTestCase(unittest.SyncV2Params, BaseSimulatorIndexesTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSimulatorIndexesTestCase(unittest.SyncBridgeParams, SyncV2SimulatorIndexesTestCase):
    __test__ = True
