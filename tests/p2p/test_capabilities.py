from hathor.conf import HathorSettings
from hathor.simulator import FakeConnection
from tests import unittest

settings = HathorSettings()


class HathorCapabilitiesTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

    def test_capabilities(self):
        network = 'testnet'
        manager1 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST])
        manager2 = self.create_peer(network, capabilities=[])

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Even if we don't have the capability we must connect because the whitelist url conf is None
        self.assertEqual(conn._proto1.state.state_name, 'READY')
        self.assertEqual(conn._proto2.state.state_name, 'READY')

        manager3 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST])
        manager4 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST])

        conn2 = FakeConnection(manager3, manager4)

        # Run the p2p protocol.
        for _ in range(100):
            conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertEqual(conn2._proto1.state.state_name, 'READY')
        self.assertEqual(conn2._proto2.state.state_name, 'READY')
