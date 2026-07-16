# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.feature_activation.feature_service import FeatureService
from hathor.manager import HathorManager
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopWhenSynced, StopWhenTrue
from hathor.verification.vertex_verifier import VertexVerifier
from hathor_tests.simulation.base import SimulatorTestCase


class RandomSimulatorTestCase(SimulatorTestCase):
    @staticmethod
    def _network_converged(reference: HathorManager, others: list[HathorManager]) -> bool:
        """Return True when every manager in `others` has the same best block and mempool tips
        as `reference`, i.e. the whole network has converged.

        This checks convergence directly on each node's storage, independent of the state of
        individual peer connections. A single connection may stay stuck (e.g. flapping on a
        sync-v2 streaming error) without preventing the network from converging through the
        other connections, so it is a more reliable stop condition than requiring every
        connection to report itself as synced.
        """
        best_block = reference.tx_storage.get_best_block_hash()
        mempool_tips = reference.tx_storage.indexes.mempool_tips.get()
        return all(
            node.tx_storage.get_best_block_hash() == best_block
            and node.tx_storage.indexes.mempool_tips.get() == mempool_tips
            for node in others
        )

    def test_verify_pow(self) -> None:
        manager1 = self.create_peer()
        # just get one of the genesis, we don't really need to create any transaction
        tx = next(iter(manager1.tx_storage.get_all_genesis()))
        # optional argument must be valid, it just has to not raise any exception, there's no assert for that
        feature_service = FeatureService(settings=self._settings, tx_storage=manager1.tx_storage)
        VertexVerifier(
            reactor=self.reactor,
            settings=self._settings,
            feature_service=feature_service
        ).verify_pow(tx, override_weight=0.)

    def test_one_node(self) -> None:
        manager1 = self.create_peer()

        miner1 = self.simulator.create_miner(manager1, hashpower=100e6)
        miner1.start()
        self.simulator.run(10)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=2 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(60 * 60)

        # FIXME: the setup above produces 0 new blocks and transactions
        # self.assertGreater(manager1.tx_storage.get_vertices_count(), 3)

    def test_two_nodes(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.simulator.run(10)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(60)

        conn12 = FakeConnection(manager1, manager2, latency=0.150)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        miner2 = self.simulator.create_miner(manager2, hashpower=10e9)
        miner2.start()
        self.simulator.run(120)

        gen_tx2 = self.simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()
        self.simulator.run(10 * 60)

        miner1.stop()
        miner2.stop()
        gen_tx1.stop()
        gen_tx2.stop()

        self.assertTrue(self.simulator.run(3000, trigger=StopWhenSynced(conn12)))

        self.assertTrue(conn12.is_connected)
        self.assertTipsEqual(manager1, manager2)

    def test_many_miners_since_beginning(self) -> None:
        nodes: list[HathorManager] = []
        miners = []

        for hashpower in [10e6, 5e6, 1e6, 1e6, 1e6]:
            manager = self.create_peer()
            for node in nodes:
                # XXX: using autoreconnect is more realistic, but ideally it shouldn't be needed, but the test is
                #      failing without it for some reason
                conn = FakeConnection(manager, node, latency=0.085, autoreconnect=True)
                self.simulator.add_connection(conn)

            nodes.append(manager)

            miner = self.simulator.create_miner(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

        self.simulator.run(600)

        for miner in miners:
            miner.stop()

        # The network must fully converge within the time budget, so the tip comparison below
        # reflects a converged network instead of an arbitrary moment in time.
        converged = StopWhenTrue(lambda: self._network_converged(nodes[0], nodes[1:]))
        self.assertTrue(self.simulator.run(3600, trigger=converged))

        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)

    def test_new_syncing_peer(self) -> None:
        nodes = []
        miners = []
        tx_generators = []

        manager = self.create_peer()
        nodes.append(manager)
        miner = self.simulator.create_miner(manager, hashpower=10e6)
        miner.start()
        miners.append(miner)
        self.simulator.run(600)

        for hashpower in [10e6, 8e6, 5e6]:
            manager = self.create_peer()
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085, autoreconnect=True)
                self.simulator.add_connection(conn)
            nodes.append(manager)

            miner = self.simulator.create_miner(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

        for i, rate in enumerate([5, 4, 3]):
            tx_gen = self.simulator.create_tx_generator(nodes[i], rate=rate * 1 / 60., hashpower=1e6,
                                                        ignore_no_funds=True)
            tx_gen.start()
            tx_generators.append(tx_gen)

        self.simulator.run(600)

        self.log.debug('adding late node')
        late_manager = self.create_peer()
        for node in nodes:
            conn = FakeConnection(late_manager, node, latency=0.300, autoreconnect=True)
            self.simulator.add_connection(conn)

        self.simulator.run(600)

        for tx_gen in tx_generators:
            tx_gen.stop()
        for miner in miners:
            miner.stop()

        # The late node must fully converge with the network within the time budget. This
        # asserts convergence actually happened, instead of merely checking consensus at an
        # arbitrary cutoff (which would silently pass even if sync never completed).
        converged = StopWhenTrue(lambda: self._network_converged(late_manager, nodes))
        self.assertTrue(self.simulator.run(3600, trigger=converged))

        for idx, node in enumerate(nodes):
            self.log.debug(f'checking node {idx}')
            self.assertConsensusValid(node)
            self.assertConsensusEqual(node, late_manager)
