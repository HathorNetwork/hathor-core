import random

from mnemonic import Mnemonic

from hathor.graphviz import GraphvizVisualizer
from hathor.manager import TestMode
from hathor.wallet import HDWallet
from tests import unittest
from tests.utils import (
    FakeConnection,
    add_blocks_unlock_reward,
    add_new_block,
    add_new_double_spending,
    add_new_transactions,
)


class HathorSyncMethodsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        # import sys
        # from twisted.python import log
        # log.startLogging(sys.stdout)

        # self.set_random_seed(0)

        from hathor.transaction.genesis import _get_genesis_transactions_unsafe
        first_timestamp = min(tx.timestamp for tx in _get_genesis_transactions_unsafe(None))
        self.clock.advance(first_timestamp + random.randint(3600, 120*24*3600))

        self.network = 'testnet'

    def create_peer(self, network, unlock_wallet=True):
        wallet = HDWallet(gap_limit=2)
        wallet._manually_initialize()

        manager = super().create_peer(network, wallet=wallet)
        manager.test_mode = TestMode.TEST_ALL_WEIGHT
        manager.avg_time_between_blocks = 64

        # Don't use it anywhere else. It is unsafe to generate mnemonic words like this.
        # It should be used only for testing purposes.
        m = Mnemonic('english')
        words = m.to_mnemonic(bytes(random.randint(0, 255) for _ in range(32)))
        wallet.unlock(words=words, tx_storage=manager.tx_storage)
        return manager

    def test_split_brain(self):
        debug_pdf = False

        manager1 = self.create_peer(self.network, unlock_wallet=True)
        manager1.avg_time_between_blocks = 3

        manager2 = self.create_peer(self.network, unlock_wallet=True)
        manager2.avg_time_between_blocks = 3

        for _ in range(10):
            add_new_block(manager1, advance_clock=1)
            add_blocks_unlock_reward(manager1)
            add_new_block(manager2, advance_clock=1)
            add_blocks_unlock_reward(manager2)
            self.clock.advance(10)
            for _ in range(random.randint(3, 10)):
                add_new_transactions(manager1, random.randint(2, 4))
                add_new_transactions(manager2, random.randint(3, 7))
                add_new_double_spending(manager1)
                add_new_double_spending(manager2)
                self.clock.advance(10)
        self.clock.advance(20)

        self.assertTipsNotEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-pre')

        conn = FakeConnection(manager1, manager2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID

        empty_counter = 0
        for i in range(1000):
            if conn.is_empty():
                empty_counter += 1
                if empty_counter > 10:
                    break
            else:
                empty_counter = 0

            conn.run_one_step()
            self.clock.advance(0.2)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-post')
            dot2 = GraphvizVisualizer(manager2.tx_storage, include_verifications=True).dot()
            dot2.render('dot2-post')

        node_sync = conn.proto1.state.get_sync_plugin()
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(manager1, manager2)
        self.assertConsensusEqual(manager1, manager2)
        # self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)
