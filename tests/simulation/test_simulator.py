import random
from typing import Optional

from mnemonic import Mnemonic

from hathor.manager import TestMode
from hathor.transaction import BaseTransaction
from hathor.transaction.genesis import _get_genesis_transactions_unsafe
from hathor.wallet import HDWallet
from tests import unittest
from tests.clock import HeapClock
from tests.utils import FakeConnection, MinerSimulator, RandomTransactionGenerator, Simulator

# from twisted.internet.task import Clock


class HathorSimulatorTestCase(unittest.TestCase):
    seed_config: Optional[int] = None

    def setUp(self):
        super().setUp()

        self.clock = HeapClock()
        self.set_random_seed(self.seed_config)

        print('-'*30)
        print('Simulation seed config:', self.random_seed)
        print('-'*30)

        def verify_pow(self: BaseTransaction) -> None:
            assert self.hash is not None

        self.old_verify_pow = BaseTransaction.verify_pow
        BaseTransaction.verify_pow = verify_pow

        self.network = 'testnet'

        first_timestamp = min(tx.timestamp for tx in _get_genesis_transactions_unsafe(None))
        self.clock.advance(first_timestamp + random.randint(3600, 120*24*3600))

    def tearDown(self):
        BaseTransaction.verify_pow = self.old_verify_pow
        super().tearDown()

    def create_peer(self, network):
        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        manager = super().create_peer(network, wallet=wallet)
        manager.reactor = self.clock
        manager.test_mode = TestMode.DISABLED
        manager.avg_time_between_blocks = 64

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(random.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    def test_one_node(self):
        manager1 = self.create_peer(self.network)
        simulator = Simulator(self.clock)

        miner1 = MinerSimulator(manager1, hashpower=100e6)
        miner1.start()
        simulator.run(10)

        gen_tx1 = RandomTransactionGenerator(manager1, rate=2 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(60 * 60)

        print()
        print('Metrics:')
        d = {}
        for key in ['transactions', 'blocks', 'hash_rate', 'total_block_weight', 'total_tx_weight']:
            d[key] = getattr(manager1.metrics, key)
            print('  {}: {}'.format(key, getattr(manager1.metrics, key)))
        print()
        print(d)

        # dot1 = manager1.tx_storage.graphviz(format='pdf')
        # dot1.render('test_sync1')

    def test_two_nodes(self):
        # import sys
        # from twisted.python import log
        # log.startLogging(sys.stdout)

        manager1 = self.create_peer(self.network)
        manager2 = self.create_peer(self.network)

        # manager1.start_log_animation('_debug1')
        # manager2.start_log_animation('_debug2')

        simulator = Simulator(self.clock)
        miner1 = MinerSimulator(manager1, hashpower=10e6)
        miner1.start()
        simulator.run(10)

        gen_tx1 = RandomTransactionGenerator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(60)

        conn12 = FakeConnection(manager1, manager2, latency=0.150)
        simulator.add_connection(conn12)
        simulator.run(60)

        miner2 = MinerSimulator(manager2, hashpower=100e6)
        miner2.start()
        simulator.run(120)

        gen_tx2 = RandomTransactionGenerator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()
        simulator.run(10 * 60)

        miner1.stop()
        miner2.stop()
        gen_tx1.stop()
        gen_tx2.stop()

        simulator.run(5 * 60)

        print()
        print()
        print('Manager 1: Connection metrics')
        for conn in manager1.connections.get_ready_connections():
            conn.metrics.print_stats()
        print()
        print()

        # dot1 = manager1.tx_storage.graphviz(format='pdf')
        # dot1.render('test_sync1_v')

        # dot1f = manager1.tx_storage.graphviz_funds(format='pdf')
        # dot1f.render('test_sync1_f')

        self.assertTrue(conn12.is_connected)
        self.assertTipsEqual(manager1, manager2)

    def test_many_miners_since_beginning(self):
        nodes = []
        miners = []

        simulator = Simulator(self.clock)

        for hashpower in [10e6, 5e6, 1e6, 1e6, 1e6]:
            manager = self.create_peer(self.network)
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085)
                simulator.add_connection(conn)

            nodes.append(manager)

            miner = MinerSimulator(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

        simulator.run(60*60)

        for miner in miners:
            miner.stop()

        simulator.run(15)

        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)

    def test_many_nodes(self):
        manager1 = self.create_peer(self.network)
        manager2 = self.create_peer(self.network)

        nodes = [manager1, manager2]
        miners = []

        simulator = Simulator(self.clock)
        miner1 = MinerSimulator(manager1, hashpower=10e6)
        miner1.start()
        miners.append(miner1)
        simulator.run(10)

        gen_tx1 = RandomTransactionGenerator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(60)

        conn12 = FakeConnection(manager1, manager2, latency=0.150)
        simulator.add_connection(conn12)
        simulator.run(60)

        miner2 = MinerSimulator(manager2, hashpower=100e6)
        miner2.start()
        miners.append(miner2)
        simulator.run(120)

        gen_tx2 = RandomTransactionGenerator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()
        simulator.run(10 * 60)

        print()
        print()
        print('Manager 1: Two nodes, timestamp = {}'.format(self.clock.seconds()))
        for conn in manager1.connections.get_ready_connections():
            conn.metrics.print_stats()
        print()
        print()

        for _ in range(4):
            tmp_manager = self.create_peer(self.network)
            for m in nodes:
                latency = random.random()
                conn = FakeConnection(tmp_manager, m, latency=latency)
                simulator.add_connection(conn)
            nodes.append(tmp_manager)
            simulator.run(10 * 60)
            print()
            print()
            print('Manager 1: {} nodes, timestamp = {}'.format(len(nodes), self.clock.seconds()))
            for conn in manager1.connections.get_ready_connections():
                conn.metrics.print_stats()
            print()
            print()

        for miner in miners:
            miner.stop()

        gen_tx1.stop()
        gen_tx2.stop()

        simulator.run(5 * 60)

        print()
        print()
        print('Manager 1: Final connection metrics')
        for conn in manager1.connections.get_ready_connections():
            conn.metrics.print_stats()
        print()
        print()

        for node in nodes[1:]:
            self.assertTipsEqual(manager1, node)

    def test_new_syncing_peer(self):
        nodes = []
        miners = []
        tx_generators = []

        simulator = Simulator(self.clock)

        for hashpower in [10e6, 8e6, 5e6, 5e6, 5e6]:
            manager = self.create_peer(self.network)
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085)
                simulator.add_connection(conn)
            nodes.append(manager)

            miner = MinerSimulator(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

        for i, rate in enumerate([5, 4, 3, 2, 1]):
            tx_gen = RandomTransactionGenerator(nodes[i], rate=rate * 1 / 60., hashpower=1e6, ignore_no_funds=True)
            tx_gen.start()
            tx_generators.append(tx_gen)

        simulator.run(45 * 60)
        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)

        late_manager = self.create_peer(self.network)
        for node in nodes:
            conn = FakeConnection(late_manager, node, latency=0.300)
            simulator.add_connection(conn)
        nodes.append(late_manager)

        simulator.run(8 * 60)

        for tx_gen in tx_generators:
            tx_gen.stop()

        for miner in miners:
            miner.stop()

        simulator.run(60)

        # dot1 = nodes[0].tx_storage.graphviz(format='pdf')
        # dot1.render('dot1tmp')
        # dot2 = late_manager.tx_storage.graphviz(format='pdf')
        # dot2.render('dot2tmp')

        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)


class HathorSimulatorSeed1TestCase(HathorSimulatorTestCase):
    seed_config = 3917895745  # Non-trivial block reorg
