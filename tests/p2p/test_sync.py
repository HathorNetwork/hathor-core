import random

from hathor.crypto.util import decode_address
from hathor.p2p.node_sync import NodeSyncTimestamp
from hathor.p2p.protocol import PeerIdState
from hathor.transaction.storage.exceptions import TransactionIsNotABlock
from hathor.transaction.storage.remote_storage import RemoteCommunicationError, TransactionRemoteStorage
from tests import unittest
from tests.utils import FakeConnection, start_remote_storage


class HathorSyncMethodsTestCase(unittest.TestCase):
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

        tx = self.manager1.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        tx.timestamp = int(self.clock.seconds())
        tx.storage = self.manager1.tx_storage
        tx.weight = 10
        tx.parents = self.manager1.get_new_tx_parents()
        tx.resolve()
        tx.verify()
        self.manager1.propagate_tx(tx)
        self.clock.advance(10)

    def _add_new_transactions(self, num_txs):
        txs = []
        for _ in range(num_txs):
            address = self.get_address(0)
            value = random.choice([5, 10, 50, 100, 120])
            tx = self._add_new_tx(address, value)
            txs.append(tx)
        return txs

    def _add_new_block(self):
        block = self.manager1.generate_mining_block()
        self.assertTrue(block.resolve())
        block.verify()
        self.manager1.propagate_tx(block)
        self.clock.advance(10)
        return block

    def _add_new_blocks(self, num_blocks):
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block())
        return blocks

    def test_get_blocks_before(self):
        genesis_block = self.genesis_blocks[0]
        result = self.manager1.tx_storage.get_blocks_before(genesis_block.hash)
        self.assertEqual(0, len(result))

        genesis_tx = [tx for tx in self.genesis if not tx.is_block][0]
        if isinstance(self.manager1.tx_storage, TransactionRemoteStorage):
            with self.assertRaises(RemoteCommunicationError):
                self.manager1.tx_storage.get_blocks_before(genesis_tx.hash)
        else:
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

    def test_block_sync_only_genesis(self):
        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        conn.run_one_step()  # READY

        node_sync = conn.proto1.state.get_sync_plugin()
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

        node_sync = conn.proto1.state.get_sync_plugin()
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

        node_sync = conn.proto1.state.get_sync_plugin()
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

        node_sync = conn.proto1.state.get_sync_plugin()
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

        manager2 = self.create_peer(self.network)
        conn1 = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn1.is_empty():
                break
            conn1.run_one_step()
            self.clock.advance(0.1)
        self.assertTipsEqual(self.manager1, manager2)

        self._add_new_blocks(1)

        for _ in range(1000):
            if conn1.is_empty():
                break
            conn1.run_one_step()
            self.clock.advance(0.1)
        self.assertTipsEqual(self.manager1, manager2)

        manager3 = self.create_peer(self.network)
        conn2 = FakeConnection(manager2, manager3)

        for _ in range(1000):
            if conn1.is_empty() and conn2.is_empty():
                break
            conn1.run_one_step()
            conn2.run_one_step()
            self.clock.advance(0.1)

        self.assertTipsEqual(self.manager1, manager2)
        self.assertTipsEqual(self.manager1, manager3)

        self._add_new_transactions(1)

        for _ in range(1000):
            if conn1.is_empty() and conn2.is_empty():
                break
            conn1.run_one_step()
            conn2.run_one_step()
            self.clock.advance(0.1)

        self.assertTipsEqual(self.manager1, manager2)
        self.assertTipsEqual(self.manager1, manager3)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager3)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusValid(manager3)

    def test_downloader(self):
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


class RemoteStorageSyncTest(HathorSyncMethodsTestCase):
    def setUp(self):
        super().setUp()
        tx_storage, self._server = start_remote_storage()

        self.manager1.tx_storage = tx_storage

    def tearDown(self):
        self._server.stop(0).wait()
        super().tearDown()
