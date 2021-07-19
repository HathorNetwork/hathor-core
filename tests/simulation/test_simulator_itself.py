import secrets
import sys
from typing import List

import pytest

from hathor.simulator import FakeConnection, Simulator
from tests import unittest

# these tests will basically setup two independent simulator instances and assert that they generate the same
# blocks and transactions to the hash throughout the execution


@pytest.mark.skipif(sys.platform == 'win32', reason='set_seed fails on Windows')
class BaseSimulatorSelfTestCase(unittest.TestCase):
    __test__ = False

    # XXX: these are known not to trigger known issues, this is fine for now because the point of these tests isn't to
    #      uncover issues from random cases (that is for test_simulator.py), but to test if the simulator itself is
    #      able to deterministically reproduce the exact same situations
    sample_seeds: List[int] = [
        103031792772610829080643568972624189575,
        107532233982330262268105170365553978335,
        122863077639990880947521731922247045712,
        131967028093207739189827495503215926497,
        13956675485136476305549003061459191914,
        142603706699510332917242369626055156474,
        14521792154497057158944647000947493977,
        159764472689140337382478312838571764596,
        161534885070998913903532429167355744154,
        16262584685609357316528277904624408647,
        174961148202549668735472204036277919066,
        175397323631883570688074448859496865890,
        187528970213721352255727735932762549647,
        19358548812237321860202781292333604576,
        195046620569419379901480573995548043549,
        200234698587069743077800830859964414383,
        201881371387283764810587583043447468757,
        231197611121406867709183280124057536282,
        234851699762334462447552736469791832212,
        235933319837286426928208257127157257383,
        236679540580478710636450481306899011416,
        23851452099641353579370680617895132732,
        244088396765466013144809041354570867926,
        256059855541636163495890466788063017840,
        257089855928997848026546380838255638324,
        25857366067190275781917275737461826453,
        26527004109494009013091265361531464386,
        274690507678017488712168965444935178342,
        28517099468603417307351993616815068698,
        287388322610506424754512513645538340799,
        295534074549263933259117183581888111906,
        300176338435744678805018567492237502319,
        308702974305539208607997184224480996619,
        317915267367738424449181065459927717879,
        320077084871668405067920009081478044265,
        327922312298630675598391852489533785610,
        330071268670629866786768360935969193674,
        339063889364423469452897626675774310214,
        34610676714425989114859114591009992335,
        37819476566031296880606790391317689765,
        38807392778781737924252956070694272480,
        39422053252818015607263184086263548238,
        41482659423981827568834173239439709790,
        48655348691307345018804800967067629803,
        49653432426308425938291569416580315553,
        51643653509248824836418320322956257974,
        77989408190464639551006902203147081175,
        79660800617974769405752272539435302515,
        86436534820547039040582253200596659990,
        93224660652538476581205802646410116994,
        97459433892793368052597390130967329002,
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

    @pytest.mark.flaky(max_runs=10, min_passes=10)
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

    @pytest.mark.flaky(max_runs=10, min_passes=10)
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
