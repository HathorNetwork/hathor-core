import pytest
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.p2p.peer_id import PeerId
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks, StopAfterNTransactions, StopWhenTrue, Trigger
from hathor.transaction.storage.traversal import DFSWalk
from tests.simulation.base import SimulatorTestCase
from tests.utils import HAS_ROCKSDB

settings = HathorSettings()


class BaseRandomSimulatorTestCase(SimulatorTestCase):
    __test__ = True

    seed_config = 16136500336960409604

    def _get_partial_blocks(self, tx_storage):
        with tx_storage.allow_partially_validated_context():
            partial_blocks = set()
            for tx in tx_storage.get_all_transactions():
                if not tx.is_block:
                    continue
                meta = tx.get_metadata()
                if meta.validation.is_partial():
                    partial_blocks.add(tx.hash)
        return partial_blocks

    def _run_restart_test(self, *, full_verification: bool, use_tx_storage_cache: bool) -> None:
        manager1 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)
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

        for _ in range(20):
            print()
        print('Starting manager2...')
        for _ in range(20):
            print()

        # Create a new peer and run sync for a while (but stop before getting synced).
        path = self.mkdtemp()
        peer_id = PeerId()
        builder2 = self.simulator.get_default_builder() \
            .set_peer_id(peer_id) \
            .disable_sync_v1() \
            .enable_sync_v2() \
            .use_rocksdb(path)

        manager2 = self.simulator.create_peer(builder2)
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # Run sync for 2 minutes so we know it's not going to complete.
        self.simulator.run(120)

        b1 = manager1.tx_storage.get_best_block()
        b2 = manager2.tx_storage.get_best_block()

        self.assertNotEqual(b1.hash, b2.hash)

        partial_blocks = self._get_partial_blocks(manager2.tx_storage)
        self.assertGreater(len(partial_blocks), 0)

        for _ in range(20):
            print()
        print('Stopping manager2...')
        for _ in range(20):
            print()

        # Stop the full node.
        conn12.disconnect(Failure(Exception('testing')))
        self.simulator.remove_connection(conn12)
        manager2.stop()
        manager2.tx_storage._rocksdb_storage.close()
        del manager2

        for _ in range(20):
            print()
        print('Restarting manager2 as manager3...')
        for _ in range(20):
            print()

        # Restart full node using the same db.
        builder3 = self.simulator.get_default_builder() \
            .set_peer_id(peer_id) \
            .disable_sync_v1() \
            .enable_sync_v2() \
            .use_rocksdb(path)

        if full_verification:
            builder3.enable_full_verification()
        else:
            builder3.disable_full_verification()

        if use_tx_storage_cache:
            builder3.use_tx_storage_cache()

        manager3 = self.simulator.create_peer(builder3)
        self.assertEqual(partial_blocks, self._get_partial_blocks(manager3.tx_storage))
        self.assertTrue(manager3.tx_storage.indexes.deps.has_needed_tx())

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

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_restart_fullnode_full_verification(self):
        self._run_restart_test(full_verification=True, use_tx_storage_cache=False)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_restart_fullnode_quick(self):
        self._run_restart_test(full_verification=False, use_tx_storage_cache=False)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_restart_fullnode_quick_with_cache(self):
        self._run_restart_test(full_verification=False, use_tx_storage_cache=True)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_restart_fullnode_full_verification_with_cache(self):
        self._run_restart_test(full_verification=True, use_tx_storage_cache=True)

    def test_exceeds_streaming_and_mempool_limits(self) -> None:
        manager1 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)
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
        peer_id = PeerId()
        builder2 = self.simulator.get_default_builder() \
            .set_peer_id(peer_id) \
            .disable_sync_v1() \
            .enable_sync_v2() \

        manager2 = self.simulator.create_peer(builder2)
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # Let the connection start to sync.
        self.simulator.run(1)

        # Change manager1 default streaming and mempool limits.
        sync1 = conn12.proto1.state.sync_agent
        sync1.DEFAULT_STREAMING_LIMIT = 30
        sync1.mempool_manager.MAX_STACK_LENGTH = 30
        self.assertIsNone(sync1.blockchain_streaming)
        self.assertIsNone(sync1.transactions_streaming)

        # Change manager2 default streaming and mempool limits.
        sync2 = conn12.proto2.state.sync_agent
        sync2.DEFAULT_STREAMING_LIMIT = 50
        sync2.mempool_manager.MAX_STACK_LENGTH = 50
        self.assertIsNone(sync2.blockchain_streaming)
        self.assertIsNone(sync2.transactions_streaming)

        # Run until fully synced.
        # trigger = StopWhenTrue(sync2.is_synced)
        # self.assertTrue(self.simulator.run(5400, trigger=trigger))
        self.simulator.run(3600)

        self.assertEqual(manager1.tx_storage.get_vertices_count(), manager2.tx_storage.get_vertices_count())
        self.assertConsensusEqualSyncV2(manager1, manager2)
