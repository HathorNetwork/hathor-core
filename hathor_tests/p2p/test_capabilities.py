from hathor.p2p.states import ReadyState
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.simulator import FakeConnection
from hathor_tests import unittest


class CapabilitiesTestCase(unittest.TestCase):
    def test_capabilities(self) -> None:
        network = 'testnet'
        manager1 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_WHITELIST,
                                                           self._settings.CAPABILITY_SYNC_VERSION])
        manager2 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_SYNC_VERSION])

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Even if we don't have the capability we must connect because the whitelist url conf is None
        assert isinstance(conn._proto1.state, ReadyState)
        assert isinstance(conn._proto2.state, ReadyState)
        self.assertEqual(conn._proto1.state.state_name, 'READY')
        self.assertEqual(conn._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn._proto1.state.sync_agent, NodeBlockSync)
        self.assertIsInstance(conn._proto2.state.sync_agent, NodeBlockSync)

        manager3 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_WHITELIST,
                                                           self._settings.CAPABILITY_SYNC_VERSION])
        manager4 = self.create_peer(network, capabilities=[self._settings.CAPABILITY_WHITELIST,
                                                           self._settings.CAPABILITY_SYNC_VERSION])

        conn2 = FakeConnection(manager3, manager4)

        # Run the p2p protocol.
        for _ in range(100):
            conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        assert isinstance(conn2._proto1.state, ReadyState)
        assert isinstance(conn2._proto2.state, ReadyState)
        self.assertEqual(conn2._proto1.state.state_name, 'READY')
        self.assertEqual(conn2._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn2._proto1.state.sync_agent, NodeBlockSync)
        self.assertIsInstance(conn2._proto2.state.sync_agent, NodeBlockSync)
