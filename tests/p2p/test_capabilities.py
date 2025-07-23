from hathor.p2p.states import ReadyState
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.simulator import FakeConnection
from tests import unittest


class CapabilitiesTestCase(unittest.TestCase):
    def test_capabilities(self) -> None:
        network = 'testnet'
        manager1 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_WHITELIST,
                                                           self._settings.CAPABILITY_SYNC_VERSION],
                                    url_whitelist=True)
        manager2 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_WHITELIST,
                                                           self._settings.CAPABILITY_SYNC_VERSION],
                                    url_whitelist=True)

        assert manager1.connections.peers_whitelist is not None, 'Peers whitelist should not be None'
        assert manager2.connections.peers_whitelist is not None, 'Peers whitelist should not be None'
        assert len(manager1.connections.peers_whitelist._current) == 0, 'Should have no peers in the whitelist'
        assert len(manager2.connections.peers_whitelist._current) == 0, 'Should have no peers in the whitelist'

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Update: Now, the URL has no effect to block the handle hello in HelloState -
        # having capability or not is definitive to  block the conn.
        # Also, no more need to create two connections, one is enough to test the capabilities.
        assert isinstance(conn._proto1.state, ReadyState)
        assert isinstance(conn._proto2.state, ReadyState)
        self.assertEqual(conn._proto1.state.state_name, 'READY')
        self.assertEqual(conn._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn._proto1.state.sync_agent, NodeBlockSync)
        self.assertIsInstance(conn._proto2.state.sync_agent, NodeBlockSync)
