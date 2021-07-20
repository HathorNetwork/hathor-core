import random

from hathor.checkpoint import Checkpoint as cp
from hathor.crypto.util import decode_address
from hathor.p2p.protocol import PeerIdState
from hathor.simulator import FakeConnection
from hathor.transaction.storage.exceptions import TransactionIsNotABlock
from tests import unittest
from tests.utils import add_blocks_unlock_reward


class BaseHathorSyncMethodsTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        # import sys
        # from twisted.python import log
        # log.startLogging(sys.stdout)

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
        tx.verify()
        self.manager1.propagate_tx(tx)
        self.clock.advance(10)
        return tx

    def _add_new_transactions(self, num_txs):
        txs = []
        for _ in range(num_txs):
            address = self.get_address(0)
            value = random.choice([5, 10, 50, 100, 120])
            tx = self._add_new_tx(address, value)
            txs.append(tx)
        return txs

    def _add_new_block(self, propagate=True):
        block = self.manager1.generate_mining_block()
        self.assertTrue(block.resolve())
        block.verify()
        self.manager1.on_new_tx(block, propagate_to_peers=propagate)
        self.clock.advance(10)
        return block

    def _add_new_blocks(self, num_blocks, propagate=True):
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block(propagate=propagate))
        return blocks

    def test_block_sync_only_genesis(self):
        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        conn.run_one_step()  # READY

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)

    def test_block_sync_new_blocks(self):
        self._add_new_blocks(15)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(10000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_many_new_blocks(self):
        self._add_new_blocks(150)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        while not conn.is_empty():
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_new_blocks_and_txs(self):
        self._add_new_blocks(25)
        self._add_new_transactions(3)
        self._add_new_blocks(4)
        self._add_new_transactions(5)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            conn.run_one_step()
            self.clock.advance(0.1)

        # dot1 = self.manager1.tx_storage.graphviz(format='pdf')
        # dot1.render('dot1')

        # dot2 = manager2.tx_storage.graphviz(format='pdf')
        # dot2.render('dot2')

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_tx_propagation_nat_peers(self):
        """ manager1 <- manager2 <- manager3
        """
        self._add_new_blocks(25)

        self.manager2 = self.create_peer(self.network)
        self.conn1 = FakeConnection(self.manager1, self.manager2)

        for _ in range(1000):
            if self.conn1.is_empty():
                break
            self.conn1.run_one_step()
            self.clock.advance(0.1)
        self.assertTipsEqual(self.manager1, self.manager2)

        self._add_new_blocks(1)

        for _ in range(1000):
            if self.conn1.is_empty():
                break
            self.conn1.run_one_step()
            self.clock.advance(0.1)
        self.assertTipsEqual(self.manager1, self.manager2)

        self.manager3 = self.create_peer(self.network)
        self.conn2 = FakeConnection(self.manager2, self.manager3)

        for _ in range(1000):
            if self.conn1.is_empty() and self.conn2.is_empty():
                break
            self.conn1.run_one_step()
            self.conn2.run_one_step()
            self.clock.advance(0.1)

        self.assertTipsEqual(self.manager1, self.manager2)
        self.assertTipsEqual(self.manager1, self.manager3)

        self._add_new_transactions(1)

        for _ in range(1000):
            if self.conn1.is_empty() and self.conn2.is_empty():
                break
            self.conn1.run_one_step()
            self.conn2.run_one_step()
            self.clock.advance(0.1)

        self.assertTipsEqual(self.manager1, self.manager2)
        self.assertTipsEqual(self.manager1, self.manager3)
        self.assertConsensusEqual(self.manager1, self.manager2)
        self.assertConsensusEqual(self.manager1, self.manager3)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(self.manager2)
        self.assertConsensusValid(self.manager3)


class SyncV1HathorSyncMethodsTestCase(unittest.SyncV1Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    def test_downloader(self):
        from hathor.p2p.node_sync import NodeSyncTimestamp

        blocks = self._add_new_blocks(3)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        # Get to PEER-ID state only because when it gets to READY it will automatically sync
        conn.run_one_step()

        self.assertTrue(isinstance(conn.proto1.state, PeerIdState))
        self.assertTrue(isinstance(conn.proto2.state, PeerIdState))

        node_sync1 = NodeSyncTimestamp(conn.proto1, reactor=conn.proto1.node.reactor)
        node_sync1.start()
        node_sync2 = NodeSyncTimestamp(conn.proto2, reactor=conn.proto2.node.reactor)
        node_sync2.start()

        self.assertTrue(isinstance(conn.proto1.state, PeerIdState))
        self.assertTrue(isinstance(conn.proto2.state, PeerIdState))

        downloader = conn.proto2.connections.downloader

        deferred1 = downloader.get_tx(blocks[0].hash, node_sync1)
        deferred1.addCallback(node_sync1.on_tx_success)

        self.assertEqual(len(downloader.pending_transactions), 1)

        details = downloader.pending_transactions[blocks[0].hash]
        self.assertEqual(len(details.connections), 1)
        self.assertEqual(len(downloader.downloading_deque), 1)

        deferred2 = downloader.get_tx(blocks[0].hash, node_sync2)
        deferred2.addCallback(node_sync2.on_tx_success)

        self.assertEqual(len(downloader.pending_transactions), 1)
        self.assertEqual(len(downloader.pending_transactions[blocks[0].hash].connections), 2)
        self.assertEqual(len(downloader.downloading_deque), 1)
        self.assertEqual(deferred1, deferred2)

        details.downloading_deferred.callback(blocks[0])

        self.assertEqual(len(downloader.downloading_deque), 0)
        self.assertEqual(len(downloader.pending_transactions), 0)

        # Getting tx already downloaded
        downloader.get_tx(blocks[0].hash, node_sync1)

        self.assertEqual(len(downloader.downloading_deque), 0)

        # Adding fake tx_id to downloading deque
        downloader.downloading_deque.append('1')

        # Getting new tx
        downloader.get_tx(blocks[1].hash, node_sync1)

        self.assertEqual(len(downloader.pending_transactions), 1)

        details = downloader.pending_transactions[blocks[1].hash]
        self.assertEqual(len(details.connections), 1)
        self.assertEqual(len(downloader.downloading_deque), 2)

        details.downloading_deferred.callback(blocks[1])

        # Still 2 elements because the first one is not downloaded yet
        self.assertEqual(len(downloader.downloading_deque), 2)

        # Remove it
        downloader.downloading_deque.popleft()

        # And try again
        downloader.check_downloading_queue()
        self.assertEqual(len(downloader.downloading_deque), 0)

    def test_get_blocks_before(self):
        genesis_block = self.genesis_blocks[0]
        result = self.manager1.tx_storage.get_blocks_before(genesis_block.hash)
        self.assertEqual(0, len(result))

        genesis_tx = [tx for tx in self.genesis if not tx.is_block][0]
        with self.assertRaises(TransactionIsNotABlock):
            self.manager1.tx_storage.get_blocks_before(genesis_tx.hash)

        blocks = self._add_new_blocks(20)
        num_blocks = 5

        for i, block in enumerate(blocks):
            result = self.manager1.tx_storage.get_blocks_before(block.hash, num_blocks=num_blocks)

            expected_result = [genesis_block] + blocks[:i]
            expected_result = expected_result[-num_blocks:]
            expected_result = expected_result[::-1]
            self.assertEqual(result, expected_result)


class SyncV2HathorSyncMethodsTestCase(unittest.SyncV2Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    def test_sync_metadata(self):
        # test if the synced peer will build all tx metadata correctly

        height = 0
        # add a mix of blocks and transactions
        height += len(self._add_new_blocks(8))
        height += len(add_blocks_unlock_reward(self.manager1))
        self._add_new_transactions(2)
        height += len(self._add_new_blocks(1))
        self._add_new_transactions(4)
        height += len(self._add_new_blocks(2))
        self._add_new_transactions(2)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)
        conn = FakeConnection(self.manager1, manager2)

        for _ in range(100):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        # check they have the same consensus
        node_sync1 = conn.proto1.state.sync_manager
        node_sync2 = conn.proto2.state.sync_manager
        self.assertEqual(node_sync1.peer_height, height)
        self.assertEqual(node_sync1.synced_height, height)
        self.assertEqual(node_sync2.peer_height, height)
        # 3 genesis + blocks + 8 txs
        self.assertEqual(self.manager1.tx_storage.get_count_tx_blocks(), height + 11)
        self.assertEqual(manager2.tx_storage.get_count_tx_blocks(), height + 11)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(self.manager1, manager2)

        # Nodes are synced. Make sure manager2 has the correct metadata.
        for tx in self.manager1.tx_storage._topological_sort():
            meta1 = tx.get_metadata()
            meta2 = manager2.tx_storage.get_metadata(tx.hash)
            self.assertCountEqual(meta1.children or [], meta2.children or [])
            self.assertCountEqual(meta1.voided_by or [], meta2.voided_by or [])
            self.assertCountEqual(meta1.conflict_with or [], meta2.conflict_with or [])
            self.assertCountEqual(meta1.twins or [], meta2.twins or [])

    def test_tx_propagation_nat_peers(self):
        super().test_tx_propagation_nat_peers()

        node_sync1 = self.conn1.proto1.state.sync_manager
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, self.manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync1.peer_height, node_sync1.synced_height)
        self.assertEqual(node_sync1.peer_height, self.manager1.tx_storage.get_height_best_block())

        node_sync2 = self.conn2.proto1.state.sync_manager
        self.assertEqual(self.manager2.tx_storage.latest_timestamp, self.manager3.tx_storage.latest_timestamp)
        self.assertEqual(node_sync2.peer_height, node_sync2.synced_height)
        self.assertEqual(node_sync2.peer_height, self.manager2.tx_storage.get_height_best_block())

    def test_block_sync_new_blocks_and_txs(self):
        self._add_new_blocks(25)
        self._add_new_transactions(3)
        self._add_new_blocks(4)
        self._add_new_transactions(5)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            conn.run_one_step()
            self.clock.advance(0.1)

        # dot1 = self.manager1.tx_storage.graphviz(format='pdf')
        # dot1.render('dot1')

        # dot2 = manager2.tx_storage.graphviz(format='pdf')
        # dot2.render('dot2')

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync.peer_height, node_sync.synced_height)
        self.assertEqual(node_sync.peer_height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_many_new_blocks(self):
        self._add_new_blocks(150)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.peer_height, node_sync.synced_height)
        self.assertEqual(node_sync.peer_height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_new_blocks(self):
        self._add_new_blocks(15)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.peer_height, node_sync.synced_height)
        self.assertEqual(node_sync.peer_height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_full_sync(self):
        # 10 blocks
        blocks = self._add_new_blocks(10)
        # N blocks to unlock the reward
        unlock_reward_blocks = add_blocks_unlock_reward(self.manager1)
        len_reward_unlock = len(unlock_reward_blocks)
        # 3 transactions still before the last checkpoint
        self._add_new_transactions(3)
        # 5 more blocks and the last one is the last checkpoint
        new_blocks = self._add_new_blocks(5)

        LAST_CHECKPOINT = len(blocks) + len_reward_unlock + len(new_blocks)
        FIRST_CHECKPOINT = LAST_CHECKPOINT // 2
        cps = [
            cp(0, self.genesis_blocks[0].hash),
            cp(FIRST_CHECKPOINT, (blocks + unlock_reward_blocks + new_blocks)[FIRST_CHECKPOINT - 1].hash),
            cp(LAST_CHECKPOINT, (blocks + unlock_reward_blocks + new_blocks)[LAST_CHECKPOINT - 1].hash)
        ]

        # 5 blocks after the last checkpoint
        self._add_new_blocks(5)
        # 3 transactions
        self._add_new_transactions(3)
        # 5 more blocks
        self._add_new_blocks(5)

        # Add transactions to the mempool
        self._add_new_transactions(2)

        self.manager1.checkpoints = cps

        manager2 = self.create_peer(self.network)
        manager2.checkpoints = cps
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        total_count = 36 + len_reward_unlock

        self.assertEqual(self.manager1.tx_storage.get_count_tx_blocks(), total_count)
        self.assertEqual(manager2.tx_storage.get_count_tx_blocks(), 3)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        # node_sync = conn.proto1.state.sync_manager
        # self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        # self.assertTipsEqual(self.manager1, manager2)
        common_height = 25 + len_reward_unlock

        self.assertEqual(manager2.tx_storage.get_height_best_block(), common_height)
        self.assertEqual(self.manager1.tx_storage.get_height_best_block(), common_height)

        node_sync1 = conn.proto1.state.sync_manager
        node_sync2 = conn.proto2.state.sync_manager
        self.assertEqual(node_sync1.peer_height, common_height)
        self.assertEqual(node_sync1.synced_height, common_height)
        self.assertEqual(node_sync2.peer_height, common_height)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(self.manager1, manager2)

        # 3 genesis
        # 25 blocks
        # Unlock reward blocks
        # 8 txs
        self.assertEqual(self.manager1.tx_storage.get_count_tx_blocks(), total_count)
        self.assertEqual(manager2.tx_storage.get_count_tx_blocks(), total_count)
        self.assertEqual(len(manager2.tx_storage._tx_tips_index), 1)
        self.assertEqual(len(self.manager1.tx_storage._tx_tips_index), 1)

    def test_block_sync_checkpoints(self):
        LAST_CHECKPOINT = 15
        FIRST_CHECKPOINT = LAST_CHECKPOINT // 2
        blocks = self._add_new_blocks(15, propagate=False)
        cps = [
            cp(0, self.genesis_blocks[0].hash),
            cp(FIRST_CHECKPOINT, blocks[FIRST_CHECKPOINT - 1].hash),
            cp(LAST_CHECKPOINT, blocks[LAST_CHECKPOINT - 1].hash)
        ]
        self.manager1.checkpoints = cps

        manager2 = self.create_peer(self.network)
        manager2.checkpoints = cps
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        # initial connection setup
        for _ in range(100):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # do checkpoints sync
        self.clock.advance(5)
        for _ in range(100):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)
        self.assertEqual(manager2.tx_storage.get_height_best_block(), LAST_CHECKPOINT)

        # find synced timestamp
        self.clock.advance(5)
        for _ in range(10000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        node_sync1 = conn.proto1.state.sync_manager
        node_sync2 = conn.proto2.state.sync_manager
        self.assertEqual(node_sync1.peer_height, LAST_CHECKPOINT)
        self.assertEqual(node_sync1.synced_height, LAST_CHECKPOINT)
        self.assertEqual(node_sync2.peer_height, len(blocks))
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_only_genesis(self):
        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        genesis_tx = [tx for tx in self.genesis if not tx.is_block][0]
        with self.assertRaises(TransactionIsNotABlock):
            self.manager1.tx_storage.get_blocks_before(genesis_tx.hash)

        for _ in range(100):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        node_sync = conn.proto1.state.sync_manager
        self.assertEqual(node_sync.synced_height, 0)
        self.assertEqual(node_sync.peer_height, 0)

        self.assertEqual(self.manager1.tx_storage.get_count_tx_blocks(), 3)
        self.assertEqual(manager2.tx_storage.get_count_tx_blocks(), 3)


# sync-bridge should behave like sync-v2
class SyncBridgeHathorSyncMethodsTestCase(unittest.SyncBridgeParams, SyncV2HathorSyncMethodsTestCase):
    pass
