import re

from hathor.p2p.messages import ProtocolMessages
from hathor.simulator import FakeConnection, Simulator
from hathor.simulator.trigger import StopAfterMinimumBalance, StopAfterNMinedBlocks, StopWhenSendLineMatch
from hathor.util import not_none
from hathor_tests import unittest


class TriggerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.simulator = Simulator()
        self.simulator.start()

        self.manager1 = self.simulator.create_peer()
        self.manager1.allow_mining_without_peers()

        print('-' * 30)
        print('Simulation seed config:', self.simulator.seed)
        print('-' * 30)

    def tearDown(self) -> None:
        super().tearDown()
        self.simulator.stop()

    def test_stop_after_n_mined_blocks(self) -> None:
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

    def test_stop_after_minimum_balance(self) -> None:
        miner1 = self.simulator.create_miner(self.manager1, hashpower=1e6)
        miner1.start()

        wallet = not_none(self.manager1.wallet)
        settings = self.simulator.settings

        minimum_balance = 1000_00   # 16 blocks
        token_uid = settings.HATHOR_TOKEN_UID

        trigger = StopAfterMinimumBalance(wallet, token_uid, minimum_balance)
        self.assertLess(wallet.balance[token_uid].available, minimum_balance)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        self.assertGreaterEqual(wallet.balance[token_uid].available, minimum_balance)

    def test_stop_after_sendline(self) -> None:
        manager2 = self.simulator.create_peer()
        conn12 = FakeConnection(self.manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        expected_prefix = f'^{ProtocolMessages.PEER_ID.value} '.encode('ascii')
        regex = re.compile(expected_prefix)
        trigger = StopWhenSendLineMatch(conn12._proto1, regex)
        self.assertTrue(self.simulator.run(120, trigger=trigger))
