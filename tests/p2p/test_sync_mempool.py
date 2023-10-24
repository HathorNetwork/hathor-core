from hathor.crypto.util import decode_address
from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection
from tests import unittest
from tests.utils import add_blocks_unlock_reward


class BaseHathorSyncMempoolTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)
        self.manager1.avg_time_between_blocks = 4

        self.genesis = self.manager1.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def _add_new_tx(self, address, value):
        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletOutputInfo

        outputs = []
        outputs.append(
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

        tx = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager1.tx_storage)
        tx.timestamp = int(self.clock.seconds())
        tx.storage = self.manager1.tx_storage
        tx.weight = 10
        tx.parents = self.manager1.get_new_tx_parents()
        tx.resolve()
        self.manager1.verification_service.verify(tx)
        self.manager1.propagate_tx(tx)
        self.clock.advance(10)
        return tx

    def _add_new_transactions(self, num_txs):
        txs = []
        for _ in range(num_txs):
            address = self.get_address(0)
            value = self.rng.choice([5, 10, 50, 100, 120])
            tx = self._add_new_tx(address, value)
            txs.append(tx)
        return txs

    def _add_new_block(self, propagate=True):
        block = self.manager1.generate_mining_block()
        self.assertTrue(block.resolve())
        self.manager1.verification_service.verify(block)
        self.manager1.on_new_tx(block, propagate_to_peers=propagate)
        self.clock.advance(10)
        return block

    def _add_new_blocks(self, num_blocks, propagate=True):
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block(propagate=propagate))
        return blocks

    def test_mempool_basic(self):
        # 10 blocks
        self._add_new_blocks(2)
        # N blocks to unlock the reward
        add_blocks_unlock_reward(self.manager1)

        # 5 transactions to be confirmed by the next blocks
        self._add_new_transactions(5)
        # 2 more blocks
        self._add_new_blocks(2)
        # 30 transactions in the mempool
        self._add_new_transactions(30)

        debug_pdf = False
        if debug_pdf:
            dot1 = GraphvizVisualizer(self.manager1.tx_storage, include_verifications=True, include_funds=True).dot()
            dot1.render('mempool-test')

        self.manager2 = self.create_peer(self.network, enable_sync_v1=True)
        self.assertEqual(self.manager2.state, self.manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, self.manager2)
        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(self.manager2)
        self.assertConsensusEqual(self.manager1, self.manager2)


class SyncV1HathorSyncMempoolTestCase(unittest.SyncV1Params, BaseHathorSyncMempoolTestCase):
    __test__ = True


class SyncV2HathorSyncMempoolTestCase(unittest.SyncV2Params, BaseHathorSyncMempoolTestCase):
    __test__ = True

    def test_mempool_basic(self):
        super().test_mempool_basic()

        # 3 genesis
        # 25 blocks
        # Unlock reward blocks
        # 8 txs
        self.assertEqual(len(self.manager2.tx_storage.indexes.mempool_tips.get()), 1)
        self.assertEqual(len(self.manager1.tx_storage.indexes.mempool_tips.get()), 1)


# sync-bridge should behave like sync-v2
class SyncBridgeHathorSyncMempoolTestCase(unittest.SyncBridgeParams, SyncV2HathorSyncMempoolTestCase):
    pass
