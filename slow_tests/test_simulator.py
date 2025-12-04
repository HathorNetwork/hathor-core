import random

from mnemonic import Mnemonic

from hathor.transaction import BaseTransaction
from hathor.transaction.genesis import genesis_transactions
from hathor.wallet import HDWallet
from hathor_tests import unittest
from hathor_tests.clock import HeapClock
from hathor_tests.utils import FakeConnection, MinerSimulator, RandomTransactionGenerator, Simulator


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        seed_config = None
        # seed_config = 1242032928  # Strange voided transactions (with voiding blocks)
        # seed_config = 2687204330  # AssertionError
        seed_config = 965623467

        self.clock = HeapClock()
        self.set_random_seed(seed_config)

        print('-'*30)
        print('Simulation seed config:', self.random_seed)
        print('-'*30)

        def verify_pow(_) -> None:
            pass

        self.old_verify_pow = BaseTransaction.verify_pow
        BaseTransaction.verify_pow = verify_pow

        self.network = 'testnet'

        first_timestamp = min(tx.timestamp for tx in genesis_transactions(None))
        self.clock.advance(first_timestamp + random.randint(3600, 120*24*3600))

    def tearDown(self):
        BaseTransaction.verify_pow = self.old_verify_pow

    def create_peer(self, network):
        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        manager = super().create_peer(network, wallet=wallet)
        manager.reactor = self.clock
        manager.test_mode = False
        manager.avg_time_between_blocks = 64

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(random.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    def test_20_nodes(self):
        nodes = []
        miners = []
        tx_generators = []

        simulator = Simulator(self.clock)

        for _ in range(1):
            hashpower = 1e6 * random.randint(1, 20)
            manager = self.create_peer(self.network)
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085)
                simulator.add_connection(conn)
            nodes.append(manager)

            miner = MinerSimulator(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

            rate = random.randint(1, 30)
            tx_gen = RandomTransactionGenerator(manager, rate=rate * 1 / 60., hashpower=1e6, ignore_no_funds=True)
            tx_gen.start()
            tx_generators.append(tx_gen)

        simulator.run(5 * 60)

        for _ in range(20):
            hashpower = 1e6 * random.randint(1, 20)
            manager = self.create_peer(self.network)
            for node in nodes:
                conn = FakeConnection(manager, node, latency=0.085)
                simulator.add_connection(conn)
            nodes.append(manager)

        simulator.run(2 * 60)
        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)

        for manager in nodes:
            miner = MinerSimulator(manager, hashpower=hashpower)
            miner.start()
            miners.append(miner)

            rate = random.randint(1, 5)
            tx_gen = RandomTransactionGenerator(manager, rate=rate * 1 / 60., hashpower=1e6, ignore_no_funds=True)
            # They will randomly send token between them.
            tx_gen.send_to = [x.wallet.get_unused_address(mark_as_used=True) for x in nodes]
            tx_gen.start()
            tx_generators.append(tx_gen)

        simulator.run(30 * 60)

        print()
        print()
        print('Manager 1: Connection metrics')
        for conn in nodes[0].connections.iter_ready_connections():
            conn.metrics.print_stats()
        print()
        print()

        dot1 = nodes[0].tx_storage.graphviz(format='dot')
        dot1.render('dot1tmp')

        for tx_gen in tx_generators:
            tx_gen.stop()

        for miner in miners:
            miner.stop()

        simulator.run(60)

        for node in nodes[1:]:
            self.assertTipsEqual(nodes[0], node)
