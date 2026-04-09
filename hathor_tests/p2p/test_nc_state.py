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
        assert state1.peer_nc_block_root_id is None
        assert state2.peer_nc_block_root_id is None
        state1.send_get_block_nc_root_id(block_id)
        state2.send_get_block_nc_root_id(block_id)
        self.simulator.run(5)
        assert state1.peer_nc_block_root_id is not None
        assert state2.peer_nc_block_root_id is not None
        assert state1.peer_nc_block_root_id == state2.peer_nc_block_root_id
        peer_block_id, peer_node_id = state1.peer_nc_block_root_id
        assert peer_block_id == block_id

        # test simple GET-NC-DB-NODE/NC-DB-NODE
        assert state1.peer_nc_node is None
        assert state2.peer_nc_node is None
        state1.send_get_nc_db_node(peer_node_id)
        state2.send_get_nc_db_node(peer_node_id)
        self.simulator.run(5)
        assert state1.peer_nc_node is not None
        assert state2.peer_nc_node is not None
        assert state1.peer_nc_node == state2.peer_nc_node
        peer_node_data = state1.peer_nc_node
        # XXX: empty state is expected since there aren't any nano transactions
        expected_node_data = {
            'id': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'key': '',
        }
        assert peer_node_data == expected_node_data
