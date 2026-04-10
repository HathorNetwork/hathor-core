from typing import Any

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states import ReadyState
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor_tests.simulation.base import SimulatorTestCase


class NCStateTestCase(SimulatorTestCase):
    def test_empty_state(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        self.assertEqual(1, len(connected_peers2))

        # assert the protocol has capabilities
        # HelloState is responsible to transmite to protocol the capabilities
        protocol1 = connected_peers2[0]
        protocol2 = connected_peers1[0]
        self.assertIsNotNone(protocol1.capabilities)
        self.assertIsNotNone(protocol2.capabilities)

        # assert the protocol has the NANO_STATE capability
        self.assertIn(self._settings.CAPABILITY_NANO_STATE, protocol1.capabilities)
        self.assertIn(self._settings.CAPABILITY_NANO_STATE, protocol2.capabilities)

        # assert the protocol is in ReadyState
        state1 = protocol1.state
        state2 = protocol2.state
        assert isinstance(state1, ReadyState)
        assert isinstance(state2, ReadyState)

        # assert ReadyState commands
        nc_state_messages = [
            ProtocolMessages.GET_BLOCK_NC_ROOT_ID,
            ProtocolMessages.BLOCK_NC_ROOT_ID,
            ProtocolMessages.GET_NC_DB_NODE,
            ProtocolMessages.NC_DB_NODE,
        ]
        for state in [state1, state2]:
            for message in nc_state_messages:
                self.assertIn(message, state.cmd_map)

        # mine 20 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=5)
        self.assertTrue(self.simulator.run(1000, trigger=trigger))
        miner.stop()
        self.simulator.run(10)

        # blocks should have synced
        best_block1 = manager1.tx_storage.get_best_block()
        best_block2 = manager2.tx_storage.get_best_block()
        assert best_block1.hash == best_block2.hash
        block_id = best_block1.hash

        # test simple GET-BLOCK-NC-ROOT-ID/BLOCK-NC-ROOT-ID
        # send_get_block_nc_root_id now returns a Deferred[NodeId] directly
        assert len(state1._pending_nc_block_root_ids) == 0
        assert len(state2._pending_nc_block_root_ids) == 0
        deferred1 = state1.send_get_block_nc_root_id(block_id)
        deferred2 = state2.send_get_block_nc_root_id(block_id)
        assert block_id in state1._pending_nc_block_root_ids
        assert block_id in state2._pending_nc_block_root_ids
        root_results: list[Any] = []
        deferred1.addCallback(root_results.append)
        deferred2.addCallback(root_results.append)
        self.simulator.run(5)
        assert len(root_results) == 2
        # Results are now NodeId directly (not tuples)
        assert root_results[0] == root_results[1]
        peer_node_id = root_results[0]

        # test simple GET-NC-DB-NODE/NC-DB-NODE
        # send_get_nc_db_node now returns a Deferred[dict] directly
        assert len(state1._pending_nc_db_nodes) == 0
        assert len(state2._pending_nc_db_nodes) == 0
        deferred3 = state1.send_get_nc_db_node(peer_node_id)
        deferred4 = state2.send_get_nc_db_node(peer_node_id)
        node_results: list[Any] = []
        deferred3.addCallback(node_results.append)
        deferred4.addCallback(node_results.append)
        self.simulator.run(5)
        assert len(node_results) == 2
        assert node_results[0] == node_results[1]
        peer_node_data = node_results[0]
        # XXX: empty state is expected since there aren't any nano transactions
        expected_node_data = {
            'id': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'key': '',
        }
        assert peer_node_data == expected_node_data
