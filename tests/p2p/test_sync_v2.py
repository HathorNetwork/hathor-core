import base64
import re
from unittest.mock import patch

from twisted.internet.defer import Deferred, succeed
from twisted.python.failure import Failure

from hathor.conf.settings import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.states import ReadyState
from hathor.p2p.sync_v2.agent import NodeBlockSync, _HeightInfo
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import (
    StopAfterNMinedBlocks,
    StopAfterNTransactions,
    StopWhenSendLineMatch,
    StopWhenTrue,
    Trigger,
)
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.traversal import DFSWalk
from hathor.types import VertexId
from hathor.util import not_none
from tests.simulation.base import SimulatorTestCase


class RandomSimulatorTestCase(SimulatorTestCase):
    __test__ = True

    seed_config = 2

    def _get_partial_blocks(self, tx_storage: TransactionStorage) -> set[VertexId]:
        with tx_storage.allow_partially_validated_context():
            partial_blocks = set()
            for tx in tx_storage.get_all_transactions():
                if not tx.is_block:
                    continue
                meta = tx.get_metadata()
                if meta.validation.is_partial():
                    partial_blocks.add(tx.hash)
        return partial_blocks

    def _run_restart_test(self, *, use_tx_storage_cache: bool) -> None:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        trigger: Trigger = StopAfterNMinedBlocks(miner1, quantity=50)
        self.assertTrue(self.simulator.run(3 * 3600, trigger=trigger))

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=2., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        trigger = StopAfterNTransactions(gen_tx1, quantity=500)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))

        # Stop mining and run again to increase the mempool.
        miner1.stop()
        self.simulator.run(600)

        # Finally, stop all generators.
        gen_tx1.stop()

        # Create a new peer and run sync for a while (but stop before getting synced).
        path = self.mkdtemp()
        peer = PrivatePeer.auto_generated()
        builder2 = self.simulator.get_default_builder() \
            .set_peer(peer) \
            .use_rocksdb(path)

        manager2 = self.simulator.create_peer(builder2)
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # Run sync for 2 minutes so we know it's not going to complete.
        self.simulator.run(120)

        b1 = manager1.tx_storage.get_best_block()
        b2 = manager2.tx_storage.get_best_block()

        self.assertNotEqual(b1.hash, b2.hash)

        for _ in range(20):
            print()
        print('Stopping manager2...')
        for _ in range(20):
            print()

        # Stop the full node.
        conn12.disconnect(Failure(Exception('testing')))
        self.simulator.remove_connection(conn12)
        manager2.stop()
        assert isinstance(manager2.tx_storage, TransactionRocksDBStorage)
        manager2.tx_storage._rocksdb_storage.close()
        del manager2

        for _ in range(20):
            print()
        print('Restarting manager2 as manager3...')
        for _ in range(20):
            print()

        # Restart full node using the same db.
        builder3 = self.simulator.get_default_builder() \
            .set_peer(peer) \
            .use_rocksdb(path)

        if use_tx_storage_cache:
            builder3.use_tx_storage_cache()

        manager3 = self.simulator.create_peer(builder3)

        conn13 = FakeConnection(manager1, manager3, latency=0.05)
        self.simulator.add_connection(conn13)

        # Let the connection start to sync.
        self.simulator.run(60)

        # Run until it's synced (time out of 1h)
        sync3 = conn13.proto2.state.sync_agent
        self.simulator.run(600)
        sync3._breakpoint = True

        trigger = StopWhenTrue(sync3.is_synced)
        self.assertTrue(self.simulator.run(5400, trigger=trigger))

        self.assertEqual(manager1.tx_storage.get_vertices_count(), manager3.tx_storage.get_vertices_count())
        self.assertConsensusEqualSyncV2(manager1, manager3)

        # Start generators again to test real time sync.
        miner1.start()
        gen_tx1.start()
        self.simulator.run(600)
        miner1.stop()
        gen_tx1.stop()

        # Make sure we are all synced.
        self.simulator.run(600)

        self.assertEqual(manager1.tx_storage.get_vertices_count(), manager3.tx_storage.get_vertices_count())
        self.assertConsensusEqualSyncV2(manager1, manager3)

    def test_restart_fullnode_quick(self) -> None:
        self._run_restart_test(use_tx_storage_cache=False)

    def test_restart_fullnode_quick_with_cache(self) -> None:
        self._run_restart_test(use_tx_storage_cache=True)

    def test_exceeds_streaming_and_mempool_limits(self) -> None:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        # Find 50 blocks.
        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        trigger: Trigger = StopAfterNMinedBlocks(miner1, quantity=100)
        self.assertTrue(self.simulator.run(3 * 3600, trigger=trigger))
        miner1.stop()

        # Generate 500 txs.
        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3., hashpower=10e9, ignore_no_funds=True)
        gen_tx1.start()
        trigger = StopAfterNTransactions(gen_tx1, quantity=500)
        self.simulator.run(3600, trigger=trigger)
        self.assertGreater(manager1.tx_storage.get_vertices_count(), 500)
        gen_tx1.stop()

        # Find 1 block.
        miner1.start()
        trigger = StopAfterNMinedBlocks(miner1, quantity=1)
        self.assertTrue(self.simulator.run(3600, trigger=trigger))
        miner1.stop()

        # Confirm block has 400+ transactions.
        blk = manager1.tx_storage.get_best_block()
        tx_parents = [manager1.tx_storage.get_transaction(x) for x in blk.parents[1:]]
        self.assertEqual(len(tx_parents), 2)
        dfs = DFSWalk(manager1.tx_storage, is_dag_verifications=True, is_left_to_right=False)
        cnt = 0
        for tx in dfs.run(tx_parents):
            if tx.get_metadata().first_block == blk.hash:
                cnt += 1
            else:
                dfs.skip_neighbors(tx)
        self.assertGreater(cnt, 400)

        # Generate 500 txs in mempool.
        gen_tx1.start()
        trigger = StopAfterNTransactions(gen_tx1, quantity=500)
        self.simulator.run(3600, trigger=trigger)
        self.assertGreater(manager1.tx_storage.get_vertices_count(), 1000)
        gen_tx1.stop()

        for _ in range(20):
            print()
        print('Part 2: Start new fullnode and sync')
        for _ in range(20):
            print()

        # Create a new peer and run sync for a while (but stop before getting synced).
        peer = PrivatePeer.auto_generated()
        builder2 = self.simulator.get_default_builder() \
            .set_peer(peer) \

        manager2 = self.simulator.create_peer(builder2)
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # Let the connection start to sync.
        self.simulator.run(1)

        new_streaming_limit = 30

        # Change manager1 default streaming and mempool limits.
        sync1 = conn12.proto1.state.sync_agent
        sync1.DEFAULT_STREAMING_LIMIT = new_streaming_limit
        sync1.mempool_manager.MAX_STACK_LENGTH = new_streaming_limit
        self.assertIsNone(sync1._blk_streaming_server)
        self.assertIsNone(sync1._tx_streaming_server)

        # Change manager2 default streaming and mempool limits.
        sync2 = conn12.proto2.state.sync_agent
        sync2.DEFAULT_STREAMING_LIMIT = new_streaming_limit
        sync2.mempool_manager.MAX_STACK_LENGTH = new_streaming_limit
        self.assertIsNone(sync2._blk_streaming_server)
        self.assertIsNone(sync2._tx_streaming_server)

        # Run until fully synced.
        # trigger = StopWhenTrue(sync2.is_synced)
        # self.assertTrue(self.simulator.run(5400, trigger=trigger))
        self.simulator.run(3600)

        self.assertEqual(manager1.tx_storage.get_vertices_count(), manager2.tx_storage.get_vertices_count())
        self.assertConsensusEqualSyncV2(manager1, manager2)

    def test_receiving_tips_limit(self) -> None:
        from hathor.manager import HathorManager
        from hathor.transaction import Transaction
        from hathor.wallet.base_wallet import WalletOutputInfo
        from tests.utils import BURN_ADDRESS

        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        # Find 100 blocks.
        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        trigger: Trigger = StopAfterNMinedBlocks(miner1, quantity=100)
        self.assertTrue(self.simulator.run(3 * 3600, trigger=trigger))
        miner1.stop()

        # Custom tx generator that generates tips
        parents = manager1.get_new_tx_parents(manager1.tx_storage.latest_timestamp)

        def custom_gen_new_tx(manager: HathorManager, _address: str, value: int) -> Transaction:
            outputs = []
            # XXX: burn address guarantees that this output will not be used as input for any following transactions
            # XXX: reduce value to make sure we can generate more transactions, otherwise it will spend a linear random
            #      percent from 1 to 100 of the available balance, this way it spends from 0.1% to 10%
            outputs.append(WalletOutputInfo(address=BURN_ADDRESS, value=max(1, int(value / 10)), timelock=None))

            assert manager.wallet is not None
            tx = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
            tx.storage = manager.tx_storage

            max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
            tx.timestamp = max(max_ts_spent_tx + 1, int(manager.reactor.seconds()))

            tx.weight = 1
            # XXX: fixed parents is the final requirement to make all the generated new tips
            tx.parents = parents
            manager.cpu_mining_service.resolve(tx)
            return tx

        # Generate 100 tx-tips in mempool.
        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3., hashpower=10e9, ignore_no_funds=True)
        gen_tx1.gen_new_tx = custom_gen_new_tx
        gen_tx1.start()
        trigger = StopAfterNTransactions(gen_tx1, quantity=100)
        self.simulator.run(3600, trigger=trigger)
        self.assertGreater(manager1.tx_storage.get_vertices_count(), 100)
        gen_tx1.stop()
        assert manager1.tx_storage.indexes is not None
        assert manager1.tx_storage.indexes.mempool_tips is not None
        mempool_tips_count = len(manager1.tx_storage.indexes.mempool_tips.get())
        # we should expect at the very least 30 tips
        self.assertGreater(mempool_tips_count, 30)

        # Create a new peer and run sync for a while (but stop before getting synced).
        peer = PrivatePeer.auto_generated()
        builder2 = self.simulator.get_default_builder() \
            .set_peer(peer)

        manager2 = self.simulator.create_peer(builder2)
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # Let the connection start to sync.
        self.simulator.run(1)

        # Run until blocks are synced
        sync2 = conn12.proto2.state.sync_agent
        trigger = StopWhenTrue(sync2.is_synced)
        self.assertTrue(self.simulator.run(300, trigger=trigger))

        # Change manager2's max_running_time to check if it correctly closes the connection
        # 10 < 30, so this should be strict enough that it will fail
        sync2.max_receiving_tips = 10
        self.assertIsNone(sync2._blk_streaming_server)
        self.assertIsNone(sync2._tx_streaming_server)

        # This should fail because the get tips should be rejected because it exceeds the limit
        self.simulator.run(300)
        # we should expect only the tips to be missing from the second node
        self.assertEqual(manager1.tx_storage.get_vertices_count(),
                         manager2.tx_storage.get_vertices_count() + mempool_tips_count)
        # and also the second node should have aborted the connection
        self.assertTrue(conn12.proto2.aborting)

    def _prepare_sync_v2_find_best_common_block_reorg(self) -> FakeConnection:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()
        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.assertTrue(self.simulator.run(24 * 3600))
        miner1.stop()

        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        self.assertTrue(self.simulator.run(3600))
        return conn12

    async def test_sync_v2_find_best_common_block_reorg_1(self) -> None:
        conn12 = self._prepare_sync_v2_find_best_common_block_reorg()
        assert isinstance(conn12._proto1.state, ReadyState)
        sync_agent = conn12._proto1.state.sync_agent
        assert isinstance(sync_agent, NodeBlockSync)
        rng = conn12.manager2.rng

        my_best_block = sync_agent.get_my_best_block()
        peer_best_block = not_none(sync_agent.peer_best_block)

        fake_peer_best_block = _HeightInfo(my_best_block.height + 3, rng.randbytes(32))
        reorg_height = peer_best_block.height - 50

        def fake_get_peer_block_hashes(heights: list[int]) -> Deferred[list[_HeightInfo]]:
            # return empty as soon as the search lowest height is not the genesis
            if heights[0] != 0:
                return succeed([])

            # simulate a reorg
            response = []
            for h in heights:
                if h < reorg_height:
                    index_manager = not_none(conn12.manager2.tx_storage.indexes)
                    vertex_id = not_none(index_manager.height.get(h))
                else:
                    vertex_id = rng.randbytes(32)
                response.append(_HeightInfo(height=h, id=vertex_id))
            return succeed(response)

        with patch.object(sync_agent, 'get_peer_block_hashes', new=fake_get_peer_block_hashes):
            common_block_info = await sync_agent.find_best_common_block(my_best_block, fake_peer_best_block)
            self.assertIsNone(common_block_info)

    async def test_sync_v2_find_best_common_block_reorg_2(self) -> None:
        conn12 = self._prepare_sync_v2_find_best_common_block_reorg()
        assert isinstance(conn12._proto1.state, ReadyState)
        sync_agent = conn12._proto1.state.sync_agent
        assert isinstance(sync_agent, NodeBlockSync)
        rng = conn12.manager2.rng

        my_best_block = sync_agent.get_my_best_block()
        peer_best_block = not_none(sync_agent.peer_best_block)

        fake_peer_best_block = _HeightInfo(my_best_block.height + 3, rng.randbytes(32))
        reorg_height = peer_best_block.height - 50

        def fake_get_peer_block_hashes(heights: list[int]) -> Deferred[list[_HeightInfo]]:
            if heights[0] != 0:
                return succeed([
                    _HeightInfo(height=h, id=rng.randbytes(32))
                    for h in heights
                ])

            # simulate a reorg
            response = []
            for h in heights:
                if h < reorg_height:
                    index_manager = not_none(conn12.manager2.tx_storage.indexes)
                    vertex_id = not_none(index_manager.height.get(h))
                else:
                    vertex_id = rng.randbytes(32)
                response.append(_HeightInfo(height=h, id=vertex_id))
            return succeed(response)

        with patch.object(sync_agent, 'get_peer_block_hashes', new=fake_get_peer_block_hashes):
            common_block_info = await sync_agent.find_best_common_block(my_best_block, fake_peer_best_block)
            self.assertIsNone(common_block_info)

    def test_multiple_unexpected_txs(self) -> None:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        # mine some blocks (10, could be any amount)
        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.assertTrue(self.simulator.run(3 * 3600, trigger=StopAfterNMinedBlocks(miner1, quantity=100)))
        miner1.stop()

        # generate some transactions (10, could by any amount >1)
        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3., hashpower=10e9, ignore_no_funds=True)
        gen_tx1.start()
        self.assertTrue(self.simulator.run(3 * 3600, trigger=StopAfterNTransactions(gen_tx1, quantity=10)))
        gen_tx1.stop()

        # mine some blocks (2 to be sure, 1 should be enough)
        miner1.start()
        self.assertTrue(self.simulator.run(3 * 3600, trigger=StopAfterNMinedBlocks(miner1, quantity=2)))
        miner1.stop()

        # create a new peer and run sync and stop when it requests transactions, so we can inject it with invalid ones
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        regex = re.compile(rf'{ProtocolMessages.GET_TRANSACTIONS_BFS.value} '.encode('ascii'))
        self.assertTrue(self.simulator.run(2 * 60, trigger=StopWhenSendLineMatch(conn12._proto2, regex)))

        # make up some transactions that the node isn't expecting
        best_block = manager1.tx_storage.get_best_block()
        existing_tx = manager1.tx_storage.get_transaction(list(best_block.get_tx_parents())[0])
        fake_txs = []
        for i in range(3):
            fake_tx = existing_tx.clone()
            fake_tx.timestamp += 1 + i  # incrementally add timestamp so something is guaranteed to change
            manager1.cpu_mining_service.resolve(fake_tx)
            fake_txs.append(fake_tx)

        # send fake transactions to manager2, before the fix the first should fail with no issue, but the second would
        # end up on an AlreadyCalledError because the deferred.errback will be called twice
        for fake_tx in fake_txs:
            sync_node2 = conn12.proto2.state.sync_agent
            sync_node2.handle_transaction(base64.b64encode(fake_tx.get_struct()).decode())

        # force the processing of async code, nothing should break
        self.simulator.run(0)

    def test_update_of_slots(self) -> None:

        """
            Tests whether the slot mechanism is updating with each extra connection.
        """
        # Number of peers to connect
        max_total_peers = 5

        # Create peer list
        peerList = []
        for _ in range(max_total_peers):
            peerList.append(self.create_peer())

        # Generate incoming connections - peerList[0] is the target.
        in_connList = []
        for i in range(1, max_total_peers):
            in_connList.append(FakeConnection(peerList[0], peerList[i]))

        for i in range(len(in_connList)):
            self.simulator.add_connection(in_connList[i])

        self.simulator.run(15)

        # Checks whether it is updating incoming slot
        self.assertTrue(len(peerList[0].connections.incoming_slot.connection_slot) == len(in_connList))

        # Generate outgoing_connections - we'll make a new peer to be the outgoing reference.
        # Add new peer:

        newPeer = self.create_peer()
        out_connList = []
        for i in range(max_total_peers):
            out_connList.append(FakeConnection(peerList[i], newPeer))

        for i in range(len(out_connList)):
            self.simulator.add_connection(out_connList[i])

        self.simulator.run(15)

        # Checks whether it is updating outgoing_slot
        self.assertTrue(len(newPeer.connections.outgoing_slot.connection_slot) == len(out_connList))

    def test_slot_limit(self) -> None:
        """
            Tests whether the slots and the pool stop increasing connections after cap is reached.
        """

        # Get the settings of the max_connections allowed. Put dummy values in HathorSettings.
        _settings = HathorSettings(bytes(1), bytes(1), "testnet")

        # Number of peers and thresholds of connections in slots and pool
        number_of_peers = 45  # Note: After around 100, no more peer ids in the pool ?
        max_connections = _settings.PEER_MAX_CONNECTIONS
        max_incoming_connections = _settings.PEER_MAX_ENTRYPOINTS
        max_outgoing_connections = _settings.PEER_MAX_OUTGOING_CONNECTIONS

        # Full-Node: May receive incoming connections, deliver outgoing connections, etc.
        full_node = self.create_peer()

        # -- Check incoming connections slot -- #

        # Create peer list for incoming connections
        in_peerList = []
        for _ in range(number_of_peers):
            in_peerList.append(self.create_peer())

        # Generate incoming connections - full_node is the target.
        in_connList = []
        for i in range(0, number_of_peers):
            in_connList.append(FakeConnection(full_node, in_peerList[i]))

        for i in range(len(in_connList)):
            self.simulator.add_connection(in_connList[i])

        self.simulator.run(10)

        number_incoming_slot = len(full_node.connections.incoming_slot.connection_slot)
        # Checks whether the connection has capped on its limit size.
        self.assertTrue(number_incoming_slot == max_incoming_connections)

        # -- Check outgoing connections slot -- #

        # Create peer list for outgoing connections
        out_peerList = []
        for _ in range(number_of_peers):
            out_peerList.append(self.create_peer())

        # Generate outgoing connections - out_peerList[i] is the target.
        out_connList = []
        for i in range(0, number_of_peers):
            out_connList.append(FakeConnection(out_peerList[i], full_node))

        for i in range(len(out_connList)):
            self.simulator.add_connection(out_connList[i])

        # Assure the outgoing connections cap at the threshold.
        self.simulator.run(10)
        number_outgoing_slot = len(full_node.connections.outgoing_slot.connection_slot)
        self.assertTrue(number_outgoing_slot == max_outgoing_connections)

        # Finally, assure the number of connected peers is the same as the sum of both.
        connection_pool = full_node.connections.connections
        self.assertTrue(number_outgoing_slot + number_incoming_slot == len(connection_pool))
        self.assertTrue(len(connection_pool) <= max_connections)

    def test_check_ep_update(self) -> None:
        """
            Checks whether the check_entrypoints slot gets updated after outgoing slot full.
        """

        _settings = HathorSettings(bytes(1), bytes(1), "testnet")

        # Create exactly the amount of peers that the outgoing slot can handle
        number_of_peers = _settings.PEER_MAX_OUTGOING_CONNECTIONS
        max_check_ep_connections = _settings.PEER_MAX_CHECK_PEER_CONNECTIONS
        full_node = self.create_peer()

        out_peerList = []
        for _ in range(number_of_peers):
            out_peerList.append(self.create_peer())

        # Generate outgoing connections - out_peerList[i] is the target.
        out_connList = []
        for i in range(0, number_of_peers):
            out_connList.append(FakeConnection(out_peerList[i], full_node))

        for i in range(len(out_connList)):
            self.simulator.add_connection(out_connList[i])

        # Assure the outgoing connections cap at the threshold.
        self.simulator.run(10)

        # Now, increase in one more connection, and see if the protocol is check_entrypoints type.
        new_peer = self.create_peer()
        out_peerList.append(new_peer)
        conn = FakeConnection(new_peer, full_node)
        out_connList.append(conn)
        self.simulator.add_connection(conn)

        self.simulator.run(2)

        # Check if indeed a connection was updated into check_entrypoints after outgoing full
        self.assertTrue(len(full_node.connections.check_entrypoints_slot.connection_slot) == 1)

        # Let's keep adding more outgoing connections to the full node until it caps the check_entrypoints.
        for _ in range(10):
            out_peerList.append(self.create_peer())

        # Generate outgoing connections - out_peerList[i] is the target.
        out_connList = []
        for i in range(max_check_ep_connections + 5):
            out_connList.append(FakeConnection(out_peerList[i], full_node))

        for i in range(len(out_connList)):
            self.simulator.add_connection(out_connList[i])

        self.simulator.run(2)

        # Amount of established connections in check_ep slot.
        amount_check_ep_conn = len(full_node.connections.check_entrypoints_slot.connection_slot)

        # It passed through the cap of check_entrypoints. It mush be capped.
        self.assertTrue(amount_check_ep_conn == max_check_ep_connections)

        # Assert the numbers add up to the max of connections.
        total_conn = len(full_node.connections.connections)
        self.assertTrue(amount_check_ep_conn + number_of_peers == total_conn)
