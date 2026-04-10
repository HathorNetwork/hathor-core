from typing import Any
from unittest.mock import Mock, patch

from twisted.internet.defer import Deferred, succeed

from hathor.manager import HathorManager
from hathor.nanocontracts.nc_sync_checker import NCSyncChecker
from hathor.nanocontracts.storage.patricia_trie import NodeId
from hathor.p2p.states import ReadyState
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor_tests.simulation.base import SimulatorTestCase


class NCSyncCheckTestCase(SimulatorTestCase):
    def _create_peer_with_nc_sync_check(self, start_height: int = 0) -> HathorManager:
        builder = self.simulator.get_default_builder() \
            .set_nc_sync_check_start_height(start_height)
        return self.simulator.create_peer(builder)

    def test_compatible_state(self) -> None:
        """When both peers have the same state, sync completes without errors."""
        manager1 = self._create_peer_with_nc_sync_check()
        manager1.allow_mining_without_peers()

        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=5)
        self.assertTrue(self.simulator.run(1000, trigger=trigger))
        miner.stop()
        self.simulator.run(10)

        manager2 = self._create_peer_with_nc_sync_check()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        # Verify sync completed successfully
        best1 = manager1.tx_storage.get_best_block()
        best2 = manager2.tx_storage.get_best_block()
        self.assertEqual(best1.hash, best2.hash)

        # The block should have an nc_block_root_id
        meta = best1.get_metadata()
        self.assertIsNotNone(meta.nc_block_root_id)

    def test_incompatible_block_root(self) -> None:
        """When the peer returns a different root_id, an error should be logged."""
        manager1 = self._create_peer_with_nc_sync_check()
        manager1.allow_mining_without_peers()

        # Mine blocks and sync
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=3)
        self.assertTrue(self.simulator.run(1000, trigger=trigger))
        miner.stop()
        self.simulator.run(10)

        manager2 = self._create_peer_with_nc_sync_check()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        best_block = manager2.tx_storage.get_best_block()
        meta = best_block.get_metadata()
        self.assertIsNotNone(meta.nc_block_root_id)

        # Get the NC sync checker from the vertex handler
        nc_sync_checker = manager2.vertex_handler._nc_sync_checker
        assert isinstance(nc_sync_checker, NCSyncChecker)

        # Get a ready state from a connected peer to mock
        state2 = conn12.proto2.state
        assert isinstance(state2, ReadyState)

        # Mock send_get_block_nc_root_id to return a different root_id.
        # The refactored API returns a Deferred[NodeId] directly.
        fake_root = NodeId(b'\xff' * 32)

        def fake_send_get_block_nc_root_id(block_hash: bytes) -> Deferred[NodeId]:
            return succeed(fake_root)

        mock_log = Mock()
        original_log = state2.log

        mock_reactor_stop = Mock()
        original_running = nc_sync_checker._reactor.running

        with patch.object(state2, 'send_get_block_nc_root_id', new=fake_send_get_block_nc_root_id), \
             patch.object(nc_sync_checker._reactor, 'stop', mock_reactor_stop):
            nc_sync_checker._reactor.running = True
            state2.log = mock_log
            d = Deferred.fromCoroutine(nc_sync_checker.check_block(best_block))
            result: list[Any] = []
            d.addCallback(result.append)
            d.addErrback(result.append)

        state2.log = original_log
        nc_sync_checker._reactor.running = original_running

        # Check that 'incompatible block state' error was logged
        error_calls = [c for c in mock_log.error.call_args_list if c[0][0] == 'incompatible block state']
        self.assertTrue(
            len(error_calls) > 0,
            f'Expected "incompatible block state" error log, got: {mock_log.error.call_args_list}'
        )

        # Check that the reactor was stopped
        mock_reactor_stop.assert_called_once()
