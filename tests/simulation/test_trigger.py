from hathor.p2p.peer_id import PeerId
from hathor.simulator import Simulator
from hathor.simulator.trigger import StopAfterMinimumBalance, StopAfterNMinedBlocks
from tests import unittest


class TriggerTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.simulator = Simulator()
        self.simulator.start()

        peer_id = PeerId()
        self.manager1 = self.simulator.create_peer(peer_id=peer_id)
        self.manager1.allow_mining_without_peers()

        print('-' * 30)
        print('Simulation seed config:', self.simulator.seed)
        print('-' * 30)

    def tearDown(self):
        super().tearDown()
        self.simulator.stop()

    def test_stop_after_n_mined_blocks(self):
        miner1 = self.simulator.create_miner(self.manager1, hashpower=1e6)
        miner1.start()

        reactor = self.simulator.get_reactor()

        t0 = reactor.seconds()
        trigger = StopAfterNMinedBlocks(miner1, quantity=3)
        self.assertEqual(miner1.get_blocks_found(), 0)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        self.assertEqual(miner1.get_blocks_found(), 3)
        self.assertLess(reactor.seconds(), t0 + 3600)

        trigger.reset()
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        self.assertEqual(miner1.get_blocks_found(), 6)

        t0 = reactor.seconds()
        trigger = StopAfterNMinedBlocks(miner1, quantity=10)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        self.assertEqual(miner1.get_blocks_found(), 16)
        self.assertLess(reactor.seconds(), t0 + 3600)

    def test_stop_after_minimum_balance(self):
        miner1 = self.simulator.create_miner(self.manager1, hashpower=1e6)
        miner1.start()

        wallet = self.manager1.wallet
        settings = self.simulator.settings

        minimum_balance = 1000_00   # 16 blocks
        token_uid = settings.HATHOR_TOKEN_UID

        trigger = StopAfterMinimumBalance(wallet, token_uid, minimum_balance)
        self.assertLess(wallet.balance[token_uid].available, minimum_balance)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        self.assertGreaterEqual(wallet.balance[token_uid].available, minimum_balance)
