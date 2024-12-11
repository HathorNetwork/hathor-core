from twisted.python.failure import Failure

from hathor.checkpoint import Checkpoint as cp
from hathor.crypto.util import decode_address
from hathor.p2p.protocol import PeerIdState
from hathor.p2p.sync_version import SyncVersion
from hathor.simulator import FakeConnection
from hathor.transaction import Block, Transaction
from hathor.transaction.storage.exceptions import TransactionIsNotABlock
from hathor.transaction.weight import Weight
from hathor.util import not_none
from tests import unittest
from tests.utils import add_blocks_unlock_reward


class BaseHathorSyncMethodsTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self) -> None:
        super().setUp()

        # import sys
        # from twisted.python import log
        # log.startLogging(sys.stdout)

        self.network = 'testnet'
        self.manager1 = self.create_peer(self.network, unlock_wallet=True)
        self.manager1.avg_time_between_blocks = 4

        self.genesis = self.manager1.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]

    def _add_new_tx(self, address: str, value: int) -> Transaction:
        from hathor.wallet.base_wallet import WalletOutputInfo

        outputs = []
        outputs.append(
            WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

        tx: Transaction = self.manager1.wallet.prepare_transaction_compute_inputs(
            Transaction, outputs, self.manager1.tx_storage
        )
        tx.timestamp = int(self.clock.seconds())
        tx.storage = self.manager1.tx_storage
        tx.weight = Weight(10.0)
        tx.parents = self.manager1.get_new_tx_parents()
        self.manager1.cpu_mining_service.resolve(tx)
        self.manager1.propagate_tx(tx)
        self.clock.advance(10)
        return tx

    def _add_new_transactions(self, num_txs: int) -> list[Transaction]:
        txs = []
        for _ in range(num_txs):
            address = not_none(self.get_address(0))
            value = self.rng.choice([5, 10, 50, 100, 120])
            tx = self._add_new_tx(address, value)
            txs.append(tx)
        return txs

    def _add_new_block(self, propagate: bool = True) -> Block:
        block: Block = self.manager1.generate_mining_block()
        self.assertTrue(self.manager1.cpu_mining_service.resolve(block))
        self.manager1.on_new_tx(block, propagate_to_peers=propagate)
        self.clock.advance(10)
        return block

    def _add_new_blocks(self, num_blocks: int, propagate: bool = True) -> list[Block]:
        blocks = []
        for _ in range(num_blocks):
            blocks.append(self._add_new_block(propagate=propagate))
        return blocks

    def test_get_blocks_before(self) -> None:
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

    def test_block_sync_only_genesis(self) -> None:
        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        conn.run_one_step()  # READY

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)

    def test_block_sync_new_blocks(self) -> None:
        self._add_new_blocks(15)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(10000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_many_new_blocks(self) -> None:
        self._add_new_blocks(150)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)
        conn.disable_idle_timeout()

        while not conn.is_empty():
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_new_blocks_and_txs(self) -> None:
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

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        self.assertTipsEqual(self.manager1, manager2)
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_tx_propagation_nat_peers(self) -> None:
        """ manager1 <- manager2 <- manager3
        """
        self._add_new_blocks(25)

        self.manager2 = self.create_peer(self.network)
        self.conn1 = FakeConnection(self.manager1, self.manager2)
        self.conn1.disable_idle_timeout()

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
        self.conn2.disable_idle_timeout()

        for _ in range(1000):
            if self.conn1.is_empty() and self.conn2.is_empty():
                break
            self.conn1.run_one_step()
            self.conn2.run_one_step()
            self.clock.advance(0.1)

        self.assertTipsEqual(self.manager1, self.manager2)
        self.assertTipsEqual(self.manager1, self.manager3)

        self._add_new_transactions(1)

        for i in range(1000):
            # XXX: give it at least 100 steps before checking for emptyness
            if i > 100 and self.conn1.is_empty() and self.conn2.is_empty():
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

    def test_check_sync_state(self) -> None:
        """Tests if the LoopingCall to check the sync state works"""
        # Initially it should do nothing, since there is no recent activity
        self.manager1.check_sync_state()
        self.assertFalse(hasattr(self.manager1, "first_time_fully_synced"))

        # We force some sync activity to happen
        self._add_new_block()

        # Make sure enough time passes so the LoopingCall runs
        self.clock.advance(self.manager1.lc_check_sync_state_interval)

        # Asserts it ran correctly
        self.assertTrue(hasattr(self.manager1, "first_time_fully_synced"))
        self.assertFalse(self.manager1.lc_check_sync_state.running)


class SyncV1HathorSyncMethodsTestCase(unittest.SyncV1Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    def test_downloader(self) -> None:
        from hathor.p2p.sync_v1.agent import NodeSyncTimestamp

        blocks = self._add_new_blocks(3)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        # Get to PEER-ID state only because when it gets to READY it will automatically sync
        conn.run_one_step()

        self.assertTrue(isinstance(conn.proto1.state, PeerIdState))
        self.assertTrue(isinstance(conn.proto2.state, PeerIdState))

        downloader = conn.proto2.connections.get_sync_factory(SyncVersion.V1_1).get_downloader()

        node_sync1 = NodeSyncTimestamp(
            conn.proto1, downloader, reactor=conn.proto1.node.reactor, vertex_parser=self.manager1.vertex_parser
        )
        node_sync1.start()
        node_sync2 = NodeSyncTimestamp(
            conn.proto2, downloader, reactor=conn.proto2.node.reactor, vertex_parser=manager2.vertex_parser
        )
        node_sync2.start()

        self.assertTrue(isinstance(conn.proto1.state, PeerIdState))
        self.assertTrue(isinstance(conn.proto2.state, PeerIdState))

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

    def _downloader_bug_setup(self) -> None:
        """ This is an auxiliary method to setup a bug scenario."""
        from hathor.p2p.sync_version import SyncVersion

        # ## premise setup
        #
        # - peer_X will be self.manager
        # - peer_Y will be manager2
        # - and manager_bug will be where the bug will happen
        # add blocks
        self.blocks = self._add_new_blocks(10)
        self.tx_A = self.blocks[0]
        self.tx_B = self.blocks[1]

        # create second peer
        self.manager2 = self.create_peer(self.network)

        # connect them and sync all blocks
        self.conn0 = FakeConnection(self.manager1, self.manager2)
        for _ in range(1000):
            if self.conn0.is_empty():
                break
            self.conn0.run_one_step()
            self.clock.advance(0.1)
        else:
            self.fail('expected to break out of loop')
        self.assertTipsEqual(self.manager1, self.manager2)
        self.assertEqual(self.manager1.tx_storage.get_best_block(), self.blocks[-1])
        self.assertEqual(self.manager2.tx_storage.get_best_block(), self.blocks[-1])

        # create the peer that will experience the bug
        self.manager_bug = self.create_peer(self.network)
        self.downloader = self.manager_bug.connections.get_sync_factory(SyncVersion.V1_1).get_downloader()
        self.downloader.window_size = 1
        self.conn1 = FakeConnection(self.manager_bug, self.manager1)
        self.conn2 = FakeConnection(self.manager_bug, self.manager2)

        # put that peer in a situation where sync advanced to the point that tx_A and tx_B are requested
        for _ in range(50):
            self.conn1.run_one_step()
            if self.tx_A.hash in self.downloader.pending_transactions and \
                    self.tx_B.hash in self.downloader.pending_transactions:
                break
        else:
            self.fail('expected to break out of loop')

        # force second download after clock is advanced, this will give us enough time in between the timeouts
        self.clock.advance(10.0)
        self.downloader.start_next_download()

        for _ in range(50):
            self.conn2.run_one_step()
            details_A = self.downloader.pending_transactions.get(self.tx_A.hash)
            details_B = self.downloader.pending_transactions.get(self.tx_B.hash)
            details_A_has_conns = details_A is not None and len(details_A.connections) >= 2
            details_B_has_conns = details_B is not None and len(details_B.connections) >= 2
            if details_A_has_conns and details_B_has_conns:
                break
        else:
            self.fail('expected to break out of loop')

        # by this point everything should be set to so we can trigger the bug, any issues that happen before this
        # comment are an issue in setting up the scenario, not related to the problem itself

    def test_downloader_retry_reorder(self) -> None:
        """ Reproduce the bug that causes a reorder in the downloader queue.

        The tracking issue for this bug is #465


        In order for the bug to be triggered, the following events must happen in the following order:

        - premise:
          - be connected to two nodes which are ahead of our node (we'll call them peer_X and peer_Y)
          - sync timestamp must have requested two transactions, tx_A and tx_B, of which tx_B depends on tx_A (tx_A can
            be parent of tx_B)
        - while tx_A and tx_B are in the downloader, these are the key events that trigger the issue:
          - tx_A is requested for download to peer_X
          - tx_B is requested for download to peer_X
          - peer_X disconnects
          - peer_Y disconnects
          - download of tx_A timeouts, since there are no nodes to download it from it is removed from the downloader,
            and it is not retried
          - peer_X re-connects, sync starts and tx_A and tx_B are added to the downloader
          - peer_Y re-connects, sync starts and tx_A and tx_B are added to the downloader
          - download of tx_B timeouts, since now there are peers to download it from, it isn't removed and a retry is
            triggered
          - tx_B is downloaded, and now it will be processed before tx_A
          - tx_A is eventually downloaded (or not, this doesn't have to happen)
          - tx_B is processed, but it will fail because tx_A has not been added yet
        """
        self._downloader_bug_setup()

        # disconnect and wait for the download of tx_A to timeout but not yet the download of tx_B
        self.conn1.disconnect(Failure(Exception('testing')))
        self.conn2.disconnect(Failure(Exception('testing')))
        self.clock.advance(self._settings.GET_DATA_TIMEOUT - 10.0)

        # reconnect peer_X and peer_Y
        self.conn1 = FakeConnection(self.manager_bug, self.manager1)
        self.conn2 = FakeConnection(self.manager_bug, self.manager2)

        # proceed as normal until both peers are back to the connections list
        for _ in range(50):
            self.conn1.run_one_step()
            self.conn2.run_one_step()
            self.clock.advance(0.1)
            details_A = self.downloader.pending_transactions.get(self.tx_A.hash)
            details_B = self.downloader.pending_transactions.get(self.tx_B.hash)
            details_A_has_conns = details_A is not None and len(details_A.connections) >= 2
            details_B_has_conns = details_B is not None and len(details_B.connections) >= 2
            if details_A_has_conns and details_B_has_conns:
                break
        else:
            self.fail('expected to break out of loop')

        # wait for the download of B to be retried
        self.clock.advance(11.0)

        # this situation should cause the bug before the fix
        # just advancing the connection a little bit should be enough to finish syncing without the bug
        for _ in range(20):
            self.conn2.run_one_step()
            self.clock.advance(0.1)

        # if the fix is applied, we would see tx_A in storage by this point
        self.assertTrue(self.manager_bug.tx_storage.transaction_exists(self.tx_A.hash))

    def test_downloader_disconnect(self) -> None:
        """ This is related to test_downloader_retry_reorder, but it basically tests the change in behavior instead.

        When a peer disconnects it should be immediately removed from the tx-detail's connections list.
        """
        self._downloader_bug_setup()

        # disconnect and check if the connections were removed from the tx-details (which also means the tx-details
        # will be removed from pending_transactions)
        self.assertIn(self.tx_A.hash, self.downloader.pending_transactions)
        self.assertIn(self.tx_B.hash, self.downloader.pending_transactions)
        self.conn1.disconnect(Failure(Exception('testing')))
        self.conn2.disconnect(Failure(Exception('testing')))
        self.assertNotIn(self.tx_A.hash, self.downloader.pending_transactions)
        self.assertNotIn(self.tx_B.hash, self.downloader.pending_transactions)


class SyncV2HathorSyncMethodsTestCase(unittest.SyncV2Params, BaseHathorSyncMethodsTestCase):
    __test__ = True

    def test_sync_metadata(self) -> None:
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
        node_sync1 = conn.proto1.state.sync_agent
        node_sync2 = conn.proto2.state.sync_agent
        self.assertEqual(node_sync1.peer_best_block.height, height)
        self.assertEqual(node_sync1.synced_block.height, height)
        self.assertEqual(node_sync2.peer_best_block.height, height)
        # 3 genesis + blocks + 8 txs
        self.assertEqual(self.manager1.tx_storage.get_vertices_count(), height + 11)
        self.assertEqual(manager2.tx_storage.get_vertices_count(), height + 11)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(self.manager1, manager2)

        # Nodes are synced. Make sure manager2 has the correct metadata.
        for tx in self.manager1.tx_storage.topological_iterator():
            meta1 = tx.get_metadata()
            meta2 = manager2.tx_storage.get_metadata(tx.hash)
            self.assertCountEqual(meta1.children or [], meta2.children or [])
            self.assertCountEqual(meta1.voided_by or [], meta2.voided_by or [])
            self.assertCountEqual(meta1.conflict_with or [], meta2.conflict_with or [])
            self.assertCountEqual(meta1.twins or [], meta2.twins or [])

    def test_tx_propagation_nat_peers(self) -> None:
        super().test_tx_propagation_nat_peers()

        node_sync1 = self.conn1.proto1.state.sync_agent
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, self.manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync1.peer_best_block, node_sync1.synced_block)
        self.assertEqual(node_sync1.peer_best_block.height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, self.manager2)

        node_sync2 = self.conn2.proto1.state.sync_agent
        self.assertEqual(self.manager2.tx_storage.latest_timestamp, self.manager3.tx_storage.latest_timestamp)
        self.assertEqual(node_sync2.peer_best_block, node_sync2.synced_block)
        self.assertEqual(node_sync2.peer_best_block.height, self.manager2.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager2, self.manager3)

    def test_block_sync_new_blocks_and_txs(self) -> None:
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

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(self.manager1.tx_storage.latest_timestamp, manager2.tx_storage.latest_timestamp)
        self.assertEqual(node_sync.peer_best_block, node_sync.synced_block)
        self.assertEqual(node_sync.peer_best_block.height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_many_new_blocks(self) -> None:
        self._add_new_blocks(150)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.peer_best_block, node_sync.synced_block)
        self.assertEqual(node_sync.peer_best_block.height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_new_blocks(self) -> None:
        self._add_new_blocks(15)

        manager2 = self.create_peer(self.network)
        self.assertEqual(manager2.state, manager2.NodeState.READY)

        conn = FakeConnection(self.manager1, manager2)

        for _ in range(1000):
            if conn.is_empty():
                break
            conn.run_one_step(debug=True)
            self.clock.advance(1)

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.peer_best_block, node_sync.synced_block)
        self.assertEqual(node_sync.peer_best_block.height, self.manager1.tx_storage.get_height_best_block())
        self.assertConsensusEqual(self.manager1, manager2)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_full_sync(self) -> None:
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

        self.assertEqual(self.manager1.tx_storage.get_vertices_count(), total_count)
        self.assertEqual(manager2.tx_storage.get_vertices_count(), 3)

        conn = FakeConnection(self.manager1, manager2)
        for i in range(300):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)
        conn.run_until_empty(1000)

        # node_sync = conn.proto1.state.sync_agent
        # self.assertEqual(node_sync.synced_timestamp, node_sync.peer_timestamp)
        # self.assertTipsEqual(self.manager1, manager2)
        common_height = 25 + len_reward_unlock

        self.assertEqual(self.manager1.tx_storage.get_height_best_block(), common_height)
        self.assertEqual(manager2.tx_storage.get_height_best_block(), common_height)

        node_sync1 = conn.proto1.state.sync_agent
        node_sync2 = conn.proto2.state.sync_agent
        self.assertEqual(node_sync1.peer_best_block.height, common_height)
        self.assertEqual(node_sync1.synced_block.height, common_height)
        self.assertEqual(node_sync2.peer_best_block.height, common_height)
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)
        self.assertConsensusEqual(self.manager1, manager2)

        # 3 genesis
        # 25 blocks
        # Unlock reward blocks
        # 8 txs
        self.assertEqual(self.manager1.tx_storage.get_vertices_count(), total_count)
        self.assertEqual(manager2.tx_storage.get_vertices_count(), total_count)
        self.assertEqual(len(manager2.tx_storage.indexes.mempool_tips.get()), 1)
        self.assertEqual(len(self.manager1.tx_storage.indexes.mempool_tips.get()), 1)

    def test_block_sync_checkpoints(self) -> None:
        TOTAL_BLOCKS = 30
        LAST_CHECKPOINT = 15
        FIRST_CHECKPOINT = LAST_CHECKPOINT // 2
        blocks = self._add_new_blocks(TOTAL_BLOCKS, propagate=False)
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
            conn.run_one_step(debug=False)
            self.clock.advance(0.1)

        # find synced timestamp
        self.clock.advance(5)
        for _ in range(600):
            conn.run_one_step(debug=False)
            self.clock.advance(0.1)

        self.assertEqual(self.manager1.tx_storage.get_best_block().static_metadata.height, TOTAL_BLOCKS)
        self.assertEqual(manager2.tx_storage.get_best_block().static_metadata.height, TOTAL_BLOCKS)

        node_sync1 = conn.proto1.state.sync_agent
        node_sync2 = conn.proto2.state.sync_agent

        self.assertEqual(node_sync1.peer_best_block.height, TOTAL_BLOCKS)
        self.assertEqual(node_sync1.synced_block.height, TOTAL_BLOCKS)
        self.assertEqual(node_sync2.peer_best_block.height, len(blocks))
        self.assertConsensusValid(self.manager1)
        self.assertConsensusValid(manager2)

    def test_block_sync_only_genesis(self) -> None:
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

        node_sync = conn.proto1.state.sync_agent
        self.assertEqual(node_sync.synced_block.height, 0)
        self.assertEqual(node_sync.peer_best_block.height, 0)

        self.assertEqual(self.manager1.tx_storage.get_vertices_count(), 3)
        self.assertEqual(manager2.tx_storage.get_vertices_count(), 3)

    # TODO: an equivalent test to test_downloader, could be something like test_checkpoint_sync


# sync-bridge should behave like sync-v2
class SyncBridgeHathorSyncMethodsTestCase(unittest.SyncBridgeParams, SyncV2HathorSyncMethodsTestCase):
    pass
