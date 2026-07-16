# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import base64
import re
from typing import cast
from unittest.mock import patch

from structlog import get_logger
from twisted.internet.defer import Deferred, succeed
from twisted.python.failure import Failure

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.states import ReadyState
from hathor.p2p.sync_v2.agent import NodeBlockSync, PeerState, _HeightInfo
from hathor.p2p.sync_v2.blockchain_streaming_client import BlockchainStreamingClient
from hathor.p2p.sync_v2.exception import StreamingError
from hathor.p2p.sync_v2.streamers import StreamEnd, TransactionsStreamingServer
from hathor.p2p.sync_v2.transaction_streaming_client import TransactionStreamingClient
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import (
    StopAfterNMinedBlocks,
    StopAfterNTransactions,
    StopWhenSendLineMatch,
    StopWhenTrue,
    Trigger,
)
from hathor.transaction import Block, Transaction
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.traversal import BFSOrderWalk
from hathor.types import VertexId
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.simulation.base import SimulatorTestCase


def _make_tx_streaming_server(
    sync_agent: object,
    *,
    first_block: Block,
    last_block: Block,
) -> TransactionsStreamingServer:
    """Build a `TransactionsStreamingServer` driven directly, bypassing `__init__` (which is
    otherwise coupled to a live connection). Streaming starts at `first_block`."""
    server = object.__new__(TransactionsStreamingServer)
    server.sync_agent = cast(NodeBlockSync, sync_agent)
    server.tx_storage = server.sync_agent.tx_storage
    server.log = get_logger()
    server.first_block = first_block
    server.last_block = last_block
    server.start_from = []
    server.current_block = first_block
    server.counter = 0
    server.limit = 10_000
    server.is_running = True
    server.is_producing = True
    server.bfs = BFSOrderWalk(
        server.tx_storage, is_dag_verifications=True, is_dag_funds=True, is_left_to_right=False
    )
    server.iter = server.get_iter()
    return server


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
        cnt = len(list(blk.iter_transactions_in_this_block()))
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

    def test_sync_v2_tx_streaming_advances_past_satisfied_blocks(self) -> None:
        """Regression test for a transaction-streaming livelock during concurrent multi-peer sync.

        A block is added to the streaming `partial_blocks` list while its dependencies are still
        missing. If those dependencies are then downloaded from another peer before this peer
        streams the block's transactions, the block becomes fully satisfied with no pending
        dependencies. The client must advance past such already-satisfied leading blocks; otherwise
        it stays stuck on the first one and rejects the transactions the server legitimately sends
        for later blocks as `UnexpectedVertex`, which (with autoreconnect) loops forever.
        """
        source = self.create_peer()
        dag_builder = TestDAGBuilder.from_manager(source)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..45]
            b30 < dummy
            b40 --> txA
            b45 --> txB
        ''')
        artifacts.propagate_with(source)

        tx_a = artifacts.get_typed_vertex('txA', Transaction)
        tx_b = artifacts.get_typed_vertex('txB', Transaction)
        partial_blocks = list(artifacts.get_typed_vertices([f'b{i}' for i in range(40, 46)], Block))

        # Simulate a client that already has every vertex EXCEPT the blocks being streamed — in
        # particular it already has txA and txB, as if downloaded from another peer during
        # concurrent sync. So b40..b45 all have their dependencies satisfied even though they are
        # streamed as partial blocks. `existing` models the client's storage existence checks.
        existing: set[VertexId] = {tx.hash for tx in source.tx_storage.get_all_transactions()}
        existing -= {blk.hash for blk in partial_blocks}

        completed: list[VertexId] = []

        class FakeStorage:
            def transaction_exists(self, vertex_id: VertexId) -> bool:
                return vertex_id in existing

        class DummyProtocol:
            def __init__(self) -> None:
                self.node = source

            def get_short_peer_id(self) -> str:
                return 'dummy'

        class DummySync:
            def __init__(self) -> None:
                self.protocol = DummyProtocol()
                self.tx_storage = FakeStorage()
                self.reactor = source.reactor

            def on_block_complete(self, blk: Block, vertex_list: list[Transaction]) -> Deferred[None]:
                # Completing a block makes it available for the following block's dependencies.
                completed.append(blk.hash)
                existing.add(blk.hash)
                return succeed(None)

        client = TransactionStreamingClient(cast(NodeBlockSync, DummySync()), partial_blocks, limit=1000)
        errors: list[StreamingError] = []
        client.wait().addErrback(lambda failure: errors.append(failure.value))

        # The server streams transactions in block order: txA (confirmed by b40), then txB
        # (confirmed by b45). Both are already present, so neither is in the waiting list.
        client.handle_transaction(tx_a)
        client.handle_transaction(tx_b)
        # Pump the reactor so the queued transactions are processed.
        self.simulator.run(5)

        self.assertFalse(errors, 'should stream without rejecting already-satisfied transactions')
        # The client must advance through and complete every block, in order.
        self.assertEqual(completed, [blk.hash for blk in partial_blocks])

    def test_sync_v2_tx_streaming_advances_then_processes_tx_for_later_block(self) -> None:
        """Regression test for the advance-then-process path of the transaction-streaming client.

        This complements `test_sync_v2_tx_streaming_advances_past_satisfied_blocks`: there every
        streamed transaction already exists in storage (the `transaction_exists` branch). Here the
        client is positioned on an early block whose dependencies are already satisfied, and the
        first transaction it receives is one it genuinely still needs — but for a *later* block,
        because the server moved ahead while other peers satisfied the blocks in between. The client
        must advance past the satisfied leading blocks until the transaction becomes one it is
        waiting for, then process it normally instead of rejecting it as `UnexpectedVertex`.
        """
        source = self.create_peer()
        dag_builder = TestDAGBuilder.from_manager(source)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..45]
            b30 < dummy
            b40 --> txA
            b45 --> txB
        ''')
        artifacts.propagate_with(source)

        tx_b = artifacts.get_typed_vertex('txB', Transaction)
        partial_blocks = list(artifacts.get_typed_vertices([f'b{i}' for i in range(40, 46)], Block))

        # The client has every vertex EXCEPT the blocks being streamed and `txB`. So b40..b44 have
        # their dependencies satisfied, but b45 still needs `txB` — which the server will stream.
        existing: set[VertexId] = {tx.hash for tx in source.tx_storage.get_all_transactions()}
        existing -= {blk.hash for blk in partial_blocks}
        existing.discard(tx_b.hash)

        completed: list[VertexId] = []

        class FakeStorage:
            def transaction_exists(self, vertex_id: VertexId) -> bool:
                return vertex_id in existing

        class DummyProtocol:
            def __init__(self) -> None:
                self.node = source

            def get_short_peer_id(self) -> str:
                return 'dummy'

        class DummySync:
            def __init__(self) -> None:
                self.protocol = DummyProtocol()
                self.tx_storage = FakeStorage()
                self.reactor = source.reactor

            def on_block_complete(self, blk: Block, vertex_list: list[Transaction]) -> Deferred[None]:
                completed.append(blk.hash)
                existing.add(blk.hash)
                return succeed(None)

        client = TransactionStreamingClient(cast(NodeBlockSync, DummySync()), partial_blocks, limit=1000)
        errors: list[StreamingError] = []
        client.wait().addErrback(lambda failure: errors.append(failure.value))

        # The client starts positioned on b40. The first (and only) transaction it receives is txB,
        # which is confirmed by the last block b45 and is still genuinely missing. The client must
        # advance past b40..b44 until txB becomes a pending dependency, then process it.
        client.handle_transaction(tx_b)
        self.simulator.run(5)

        self.assertFalse(errors, 'should advance to the later block and process the needed tx')
        self.assertEqual(completed, [blk.hash for blk in partial_blocks])

    def test_sync_v2_tx_streaming_stops_when_last_block_is_voided(self) -> None:
        """The transaction-streaming server must stop when the requested `last_block` is voided.

        A reorg during streaming can move `last_block` off the best chain. Since the server walks
        the best chain, it would otherwise stream transactions confirmed by the replacement block at
        the same height, followed by later blocks. The peer did not request these transactions and
        rejects them as unexpected, which can deadlock concurrent multi-peer sync.
        """
        manager = self.create_peer()
        dag_builder = TestDAGBuilder.from_manager(manager)
        # A long main chain plus a one-block losing fork at b38. The fork block `lose1` is at the
        # same height as `b39` but is voided (off the best chain). `tx_same` is confirmed by the
        # same-height replacement, while `tx_over` is confirmed one height above `lose1`.
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..40]
            b30 < dummy
            b39 --> tx_same
            b40 --> tx_over
            blockchain b38 lose[1..1]
        ''')
        artifacts.propagate_with(manager)

        first_block = artifacts.get_typed_vertex('b35', Block)
        last_block = artifacts.get_typed_vertex('lose1', Block)
        b39 = artifacts.get_typed_vertex('b39', Block)
        b40 = artifacts.get_typed_vertex('b40', Block)
        tx_same = artifacts.get_typed_vertex('tx_same', Transaction)
        tx_over = artifacts.get_typed_vertex('tx_over', Transaction)

        # Sanity check the scenario: `last_block` is reorged out, and the two transactions are
        # confirmed respectively at the same height and one height above it.
        self.assertTrue(last_block.get_metadata().voided_by)
        self.assertEqual(not_none(tx_same.get_metadata().first_block), b39.hash)
        self.assertEqual(not_none(tx_over.get_metadata().first_block), b40.hash)
        self.assertEqual(
            not_none(b39.static_metadata.height), not_none(last_block.static_metadata.height)
        )
        self.assertGreater(
            not_none(b40.static_metadata.height), not_none(last_block.static_metadata.height)
        )

        sent: list[Transaction] = []

        class DummySync:
            def __init__(self) -> None:
                self.tx_storage = manager.tx_storage
                self.stopped: StreamEnd | None = None
                self.server: TransactionsStreamingServer | None = None

            def send_transaction(self, tx: Transaction) -> None:
                sent.append(tx)

            def stop_tx_streaming_server(self, response_code: StreamEnd) -> None:
                assert self.server is not None
                self.server.is_running = False
                self.stopped = response_code

        sync_agent = DummySync()
        server = _make_tx_streaming_server(sync_agent, first_block=first_block, last_block=last_block)
        sync_agent.server = server

        for _ in range(server.limit):
            if sync_agent.stopped is not None:
                break
            server.send_next()

        # The server must report the reorg without streaming transactions from either the
        # same-height replacement or later blocks.
        self.assertEqual(sync_agent.stopped, StreamEnd.STREAM_BECAME_VOIDED)
        sent_hashes = {tx.hash for tx in sent}
        self.assertNotIn(tx_same.hash, sent_hashes)
        self.assertNotIn(tx_over.hash, sent_hashes)

    def test_sync_v2_tx_streaming_voided_block_stops_once(self) -> None:
        """The transaction-streaming server must stop exactly once when a streamed block becomes
        voided.

        When `get_iter` reaches a block that is voided (e.g. reorged out mid-stream), it stops the
        server and ends the iterator. That makes the next `next(self.iter)` in `send_next` raise
        `StopIteration`, whose handler would stop the server a second time — crashing on the
        `assert self._tx_streaming_server is not None` in the agent. Reorgs make this happen in
        practice, so the handler must not stop an already-stopped server.
        """
        manager = self.create_peer()
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..40]
            b30 < dummy
            b40 --> tx_over
            blockchain b38 lose[1..1]
        ''')
        artifacts.propagate_with(manager)

        voided_block = artifacts.get_typed_vertex('lose1', Block)
        last_block = artifacts.get_typed_vertex('b40', Block)
        self.assertTrue(voided_block.get_metadata().voided_by)

        class DummySync:
            def __init__(self) -> None:
                self.tx_storage = manager.tx_storage
                # Mirrors the agent attribute the real `stop_tx_streaming_server` asserts on.
                self._tx_streaming_server: TransactionsStreamingServer | None = None
                self.stop_calls: list[StreamEnd] = []

            def send_transaction(self, tx: Transaction) -> None:
                pass

            def stop_tx_streaming_server(self, response_code: StreamEnd) -> None:
                # Same assertion the real agent makes — a double-stop would trip it.
                assert self._tx_streaming_server is not None
                self._tx_streaming_server.is_running = False
                self._tx_streaming_server = None
                self.stop_calls.append(response_code)

        sync_agent = DummySync()
        # Streaming starts at the voided block to reproduce the mid-stream void.
        server = _make_tx_streaming_server(sync_agent, first_block=voided_block, last_block=last_block)
        sync_agent._tx_streaming_server = server

        for _ in range(server.limit):
            if not server.is_running:
                break
            server.send_next()

        # The server must have stopped exactly once, reporting that the stream became voided.
        self.assertEqual(sync_agent.stop_calls, [StreamEnd.STREAM_BECAME_VOIDED])

    def _check_ignores_stale_end(self, *, state: PeerState, client_attr: str, handler: str) -> None:
        """A stale BLOCKS-END/TRANSACTIONS-END must be ignored, not punished by closing the
        connection.

        During concurrent multi-peer sync (especially around reorgs) a peer can finish or abort a
        stream and move on before the peer's *-END arrives. Closing the connection on such a stale
        message causes a needless reconnect that adds churn and can keep the network from
        converging.
        """
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn)
        self.simulator.run(10)

        assert isinstance(conn.proto2.state, ReadyState)
        sync_agent = conn.proto2.state.sync_agent
        assert isinstance(sync_agent, NodeBlockSync)

        # Simulate having already moved on from this stream.
        sync_agent.state = state
        setattr(sync_agent, client_attr, None)

        self.assertFalse(conn.proto2.aborting)
        getattr(sync_agent, handler)(str(int(StreamEnd.END_HASH_REACHED)))
        # The stale *-END must be ignored, leaving the connection open.
        self.assertFalse(conn.proto2.aborting)

    def test_sync_v2_ignores_stale_transactions_end(self) -> None:
        self._check_ignores_stale_end(
            state=PeerState.SYNCING_BLOCKS,
            client_attr='_tx_streaming_client',
            handler='handle_transactions_end',
        )

    def test_sync_v2_ignores_stale_blocks_end(self) -> None:
        self._check_ignores_stale_end(
            state=PeerState.SYNCING_TRANSACTIONS,
            client_attr='_blk_streaming_client',
            handler='handle_blocks_end',
        )

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
                    index_manager = conn12.manager2.tx_storage.indexes
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
                    index_manager = conn12.manager2.tx_storage.indexes
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
