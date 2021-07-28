import secrets
from typing import List

from hathor.simulator import FakeConnection, Simulator
from tests import unittest

# these tests will basically setup two independent simulator instances and assert that they generate the same
# blocks and transactions to the hash throughout the execution


class BaseSimulatorSelfTestCase(unittest.TestCase):
    __test__ = False

    # XXX: these are known not to trigger known issues, this is fine for now because the point of these tests isn't to
    #      uncover issues from random cases (that is for test_simulator.py), but to test if the simulator itself is
    #      able to deterministically reproduce the exact same situations
    sample_seeds: List[int] = [
    ]

    def setUp(self):
        super().setUp()

        seed = None
        if self.sample_seeds:
            seed = secrets.choice(self.sample_seeds)

        self.simulator1 = Simulator(seed)
        self.simulator1.start()

        self.simulator2 = Simulator(self.simulator1.seed)
        self.simulator2.start()

        self.simulator3 = Simulator(self.simulator1.seed)
        self.simulator3.start()

        print('-' * 30)
        print('Simulation seed config:', self.simulator1.seed)
        print('-' * 30)

    def tearDown(self):
        super().tearDown()

        self.simulator1.stop()
        self.simulator2.stop()
        self.simulator3.stop()

    def create_simulator_peer(self, simulator, peer_id_pool, enable_sync_v1=None, enable_sync_v2=None):
        if enable_sync_v1 is None:
            assert hasattr(self, '_enable_sync_v1'), ('`_enable_sync_v1` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v1` by argument')
            enable_sync_v1 = self._enable_sync_v1
        if enable_sync_v2 is None:
            assert hasattr(self, '_enable_sync_v2'), ('`_enable_sync_v2` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v2` by argument')
            enable_sync_v2 = self._enable_sync_v2
        assert enable_sync_v1 or enable_sync_v2, 'enable at least one sync version'
        return simulator.create_peer(
            peer_id=self.get_random_peer_id_from_pool(),
            enable_sync_v1=enable_sync_v1,
            enable_sync_v2=enable_sync_v2,
        )

    def _simulate_run(self, run_i, simulator):
        # XXX: the following was adapted from test_new_syncing_peer, it doesn't matter too much, but has good coverage
        #      of different behaviors that can be affected by non-determinism on the fullnode implementation

        self.log.debug(f'run{run_i}: simulator{run_i}')

        nodes = []
        miners = []
        tx_generators = []
        peer_id_pool = self.new_peer_id_pool()

        manager = self.create_simulator_peer(simulator, peer_id_pool)
        nodes.append(manager)
        miner = simulator.create_miner(manager, hashpower=10e6)
        miner.start()
        miners.append(miner)

        simulator.run(10)

        for i, hashpower in enumerate([10e6, 8e6, 5e6]):
            manager = self.create_simulator_peer(simulator, peer_id_pool)
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085)
                simulator.add_connection(conn)
            nodes.append(manager)
            miner = simulator.create_miner(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

        for i, rate in enumerate([5, 4, 3]):
            tx_gen = simulator.create_tx_generator(nodes[i], rate=rate * 1 / 60., hashpower=1e6, ignore_no_funds=True)
            tx_gen.start()
            tx_generators.append(tx_gen)

        simulator.run(10)

        self.log.debug(f'run{run_i}: adding late node')

        late_manager = self.create_simulator_peer(simulator, peer_id_pool)
        for node in nodes:
            conn = FakeConnection(late_manager, node, latency=0.300)
            simulator.add_connection(conn)
        nodes.append(late_manager)

        simulator.run(10)

        for tx_gen in tx_generators:
            tx_gen.stop()
        for miner in miners:
            miner.stop()

        simulator.run(10)
        return nodes

    # @pytest.mark.flaky(max_runs=10, min_passes=10)
    def test_determinism_full_runs(self):
        # sanity assert as to not mess up with it on the setup
        self.assertEqual(self.simulator1.seed, self.simulator2.seed)
        self.assertEqual(self.simulator1.seed, self.simulator3.seed)

        nodes1 = self._simulate_run(1, self.simulator1)
        nodes2 = self._simulate_run(2, self.simulator2)
        nodes3 = self._simulate_run(2, self.simulator3)

        # now we check they reached the same state

        for idx, (node1, node2, node3) in enumerate(zip(nodes1, nodes2, nodes3)):
            self.log.debug(f'checking node {idx}')
            self.assertConsensusEqual(node1, node2)
            self.assertConsensusEqual(node1, node3)

    # @pytest.mark.flaky(max_runs=10, min_passes=10)
    def test_determinism_interleaved(self):
        # sanity assert as to not mess up with it on the setup
        self.assertEqual(self.simulator1.seed, self.simulator2.seed)

        # XXX: the following was adapted from test_new_syncing_peer, it doesn't matter too much, but has good coverage
        #      of different behaviors that can be affected by non-determinism on the fullnode implementation

        nodes1 = []
        nodes2 = []
        miners1 = []
        miners2 = []
        tx_generators1 = []
        tx_generators2 = []
        peer_id_pool1 = self.new_peer_id_pool()
        peer_id_pool2 = self.new_peer_id_pool()

        self.log.debug('part1 simulator1')
        manager1 = self.create_simulator_peer(self.simulator1, peer_id_pool1)
        nodes1.append(manager1)
        miner1 = self.simulator1.create_miner(manager1, hashpower=10e6)
        miner1.start()
        miners1.append(miner1)

        self.log.debug('part1 simulator2')
        manager2 = self.create_simulator_peer(self.simulator2, peer_id_pool2)
        nodes2.append(manager2)
        miner2 = self.simulator2.create_miner(manager2, hashpower=10e6)
        miner2.start()
        miners2.append(miner2)

        for _ in range(3):
            self.simulator1.run(10)
            self.simulator2.run(10)

            for idx, (node1, node2) in enumerate(zip(nodes1, nodes2)):
                self.log.debug(f'checking node {idx}')
                self.assertConsensusEqual(node1, node2)

        for i, hashpower in enumerate([10e6, 8e6, 5e6]):
            self.log.debug(f'part2.{i} simulator1')
            manager1 = self.create_simulator_peer(self.simulator1, peer_id_pool1)
            for node in nodes1:
                conn = FakeConnection(manager1, node, latency=0.085)
                self.simulator1.add_connection(conn)
            nodes1.append(manager1)
            miner1 = self.simulator1.create_miner(manager1, hashpower=hashpower)
            miner1.start()
            miners1.append(miner1)

            self.log.debug(f'part2.{i} simulator2')
            manager2 = self.create_simulator_peer(self.simulator2, peer_id_pool2)
            for node in nodes2:
                conn = FakeConnection(manager2, node, latency=0.085)
                self.simulator2.add_connection(conn)
            nodes2.append(manager2)
            miner2 = self.simulator2.create_miner(manager2, hashpower=hashpower)
            miner2.start()
            miners2.append(miner2)

        for i, rate in enumerate([5, 4, 3]):
            self.log.debug(f'part3.{i} simulator1')
            tx_gen1 = self.simulator1.create_tx_generator(nodes1[i], rate=rate * 1 / 60., hashpower=1e6,
                                                          ignore_no_funds=True)
            tx_gen1.start()
            tx_generators1.append(tx_gen1)

            self.log.debug(f'part3.{i} simulator2')
            tx_gen2 = self.simulator2.create_tx_generator(nodes2[i], rate=rate * 1 / 60., hashpower=1e6,
                                                          ignore_no_funds=True)
            tx_gen2.start()
            tx_generators2.append(tx_gen2)

        for _ in range(3):
            self.simulator1.run(10)
            self.simulator2.run(10)

            for idx, (node1, node2) in enumerate(zip(nodes1, nodes2)):
                self.log.debug(f'checking node {idx}')
                self.assertConsensusEqual(node1, node2)

        self.log.debug('adding late node')

        self.log.debug('part4 simulator1')
        late_manager1 = self.create_simulator_peer(self.simulator1, peer_id_pool1)
        for node in nodes1:
            conn = FakeConnection(late_manager1, node, latency=0.300)
            self.simulator1.add_connection(conn)
        nodes1.append(late_manager1)

        self.log.debug('part4 simulator2')
        late_manager2 = self.create_simulator_peer(self.simulator2, peer_id_pool2)
        for node in nodes2:
            conn = FakeConnection(late_manager2, node, latency=0.300)
            self.simulator2.add_connection(conn)
        nodes2.append(late_manager2)

        for _ in range(3):
            self.simulator1.run(10)
            self.simulator2.run(10)

            for idx, (node1, node2) in enumerate(zip(nodes1, nodes2)):
                self.log.debug(f'checking node {idx}')
                self.assertConsensusEqual(node1, node2)

        self.log.debug('part5 simulator1')
        for tx_gen in tx_generators1:
            tx_gen.stop()
        for miner in miners1:
            miner.stop()

        self.log.debug('part5 simulator2')
        for tx_gen in tx_generators2:
            tx_gen.stop()
        for miner in miners2:
            miner.stop()

        for _ in range(3):
            self.simulator1.run(10)
            self.simulator2.run(10)

            for idx, (node1, node2) in enumerate(zip(nodes1, nodes2)):
                self.log.debug(f'checking node {idx}')
                self.assertConsensusEqual(node1, node2)


class SyncV1SimulatorSelfTestCase(unittest.SyncV1Params, BaseSimulatorSelfTestCase):
    __test__ = True


class SyncV2SimulatorSelfTestCase(unittest.SyncV2Params, BaseSimulatorSelfTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSimulatorSelfTestCase(unittest.SyncBridgeParams, SyncV2SimulatorSelfTestCase):
    __test__ = True
