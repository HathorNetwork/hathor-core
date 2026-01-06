import base64
import re
from typing import cast
from unittest.mock import patch

from twisted.internet.defer import Deferred, succeed
from twisted.python.failure import Failure

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.states import ReadyState
from hathor.p2p.sync_v2.agent import NodeBlockSync, _HeightInfo
from hathor.p2p.sync_v2.blockchain_streaming_client import BlockchainStreamingClient
from hathor.p2p.sync_v2.exception import StreamingError
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import (
    StopAfterNMinedBlocks,
    StopAfterNTransactions,
    StopWhenSendLineMatch,
    StopWhenTrue,
    Trigger,
)
from hathor.transaction import Block
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.traversal import DFSWalk
from hathor.types import VertexId
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.simulation.base import SimulatorTestCase


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
        peer = PrivatePeer.auto_generated()
        builder2 = self.simulator.get_default_builder() \
            .set_peer(peer)

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
        temp_dir = not_none(manager2.tx_storage._rocksdb_storage.temp_dir)
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
            .set_rocksdb_path(temp_dir)

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
        manager1 = self.create_peer()
        dag_builder = TestDAGBuilder.from_manager(manager1)

        generated_tips = '\n'.join(f'dummy <-- tx{i}' for i in range(100))
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..100]
            b10 < dummy

            {generated_tips}
        ''')
        artifacts.propagate_with(manager1)

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
                         manager2.tx_storage.get_vertices_count() + mempool_tips_count + 1)
        # and also the second node should have aborted the connection
        self.assertTrue(conn12.proto2.aborting)

    def test_sync_v2_reorg_stuck_on_repeated_blocks(self) -> None:
        manager = self.create_peer()

        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str("""
            blockchain genesis b[0..5]
            blockchain b5 lose[1..11]
            blockchain b5 win[1..12]
        """)

        # Load the losing chain.
        for node, vertex in artifacts.list:
            if node.name.startswith('lose') or node.name.startswith('b'):
                cloned = vertex.clone(include_metadata=True, include_storage=False)
                assert manager.vertex_handler.on_new_relayed_vertex(cloned)

        # Simulate a previous partial sync by adding 10 winning blocks, but not the one that would reorg.
        for i in range(1, 11):
            win_blk = artifacts.get_typed_vertex(f'win{i}', Block)
            cloned = win_blk.clone(include_metadata=False, include_storage=False)
            assert manager.vertex_handler.on_new_relayed_vertex(cloned)
            assert cloned.get_metadata().voided_by == {cloned.hash}

        win11 = artifacts.get_typed_vertex('win11', Block)
        win12 = artifacts.get_typed_vertex('win12', Block)
        start_block = artifacts.get_typed_vertex('b5', Block)

        self.assertFalse(manager.tx_storage.transaction_exists(win11.hash))
        self.assertFalse(manager.tx_storage.transaction_exists(win12.hash))

        start_info = _HeightInfo(height=start_block.get_height(), id=start_block.hash)
        end_info = _HeightInfo(height=win12.get_height(), id=win12.hash)

        class DummyProtocol:
            def get_short_peer_id(self) -> str:
                return 'dummy'

        class DummySync:
            def __init__(self) -> None:
                self.protocol = DummyProtocol()
                self.tx_storage = manager.tx_storage
                self.vertex_handler = manager.vertex_handler

        client = BlockchainStreamingClient(cast(NodeBlockSync, DummySync()), start_info, end_info)

        errors: list[StreamingError] = []
        client.wait().addErrback(lambda failure: errors.append(failure.value))

        # Restarted stream re-sends the start block and the 10 already-downloaded winning blocks before the new ones.
        stream: list[Block] = [start_block] + [
            artifacts.get_typed_vertex(f'win{i}', Block) for i in range(1, 13)
        ]
        for blk in stream:
            client.handle_blocks(blk)
            if errors:
                break

        self.assertFalse(errors, 'should stream without hitting repeated-block guard')
        self.assertTrue(manager.tx_storage.transaction_exists(win11.hash))
        self.assertTrue(manager.tx_storage.transaction_exists(win12.hash))
        best_block = manager.tx_storage.get_best_block()
        self.assertEqual(best_block.hash, win12.hash)

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
        existing_tx = manager1.tx_storage.get_transaction(list(best_block.get_tx_parents_ids())[0])
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
