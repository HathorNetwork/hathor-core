import pytest

from hathor.simulator import FakeConnection
from hathor_tests.simulation.base import SimulatorTestCase


class SimulatorIndexesTestCase(SimulatorTestCase):
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

    def setUp(self):
        super().setUp()

        # XXX: having this on the setUp makes it so when this fails it's an error (E) and not a failure (F), which has
        #      slightly different meaning
        self.manager = self._build_randomized_blockchain()

    @pytest.mark.flaky(max_runs=3, min_passes=1)
    def test_topological_iterators(self):
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
