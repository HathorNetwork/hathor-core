from hathor.conf import HathorSettings
from hathor.p2p.node_sync import NodeSyncTimestamp
from hathor.p2p.node_sync_v2 import NodeBlockSync
from hathor.simulator import FakeConnection
from tests import unittest

settings = HathorSettings()


class SyncV1HathorCapabilitiesTestCase(unittest.SyncV1Params, unittest.TestCase):
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
        self.assertIsInstance(conn._proto1.state.sync_manager, NodeSyncTimestamp)
        self.assertIsInstance(conn._proto2.state.sync_manager, NodeSyncTimestamp)

        manager3 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST])
        manager4 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST])

        conn2 = FakeConnection(manager3, manager4)

        # Run the p2p protocol.
        for _ in range(100):
            conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertEqual(conn2._proto1.state.state_name, 'READY')
        self.assertEqual(conn2._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn2._proto1.state.sync_manager, NodeSyncTimestamp)
        self.assertIsInstance(conn2._proto2.state.sync_manager, NodeSyncTimestamp)


class SyncV2HathorCapabilitiesTestCase(unittest.SyncV2Params, unittest.TestCase):
    def test_capabilities(self):
        network = 'testnet'
        manager1 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST,
                                                           settings.CAPABILITY_SYNC_VERSION])
        manager2 = self.create_peer(network, capabilities=[settings.CAPABILITY_SYNC_VERSION])

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Even if we don't have the capability we must connect because the whitelist url conf is None
        self.assertEqual(conn._proto1.state.state_name, 'READY')
        self.assertEqual(conn._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn._proto1.state.sync_manager, NodeBlockSync)
        self.assertIsInstance(conn._proto2.state.sync_manager, NodeBlockSync)

        manager3 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST,
                                                           settings.CAPABILITY_SYNC_VERSION])
        manager4 = self.create_peer(network, capabilities=[settings.CAPABILITY_WHITELIST,
                                                           settings.CAPABILITY_SYNC_VERSION])

        conn2 = FakeConnection(manager3, manager4)

        # Run the p2p protocol.
        for _ in range(100):
            conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertEqual(conn2._proto1.state.state_name, 'READY')
        self.assertEqual(conn2._proto2.state.state_name, 'READY')
        self.assertIsInstance(conn2._proto1.state.sync_manager, NodeBlockSync)
        self.assertIsInstance(conn2._proto2.state.sync_manager, NodeBlockSync)


# sync-bridge should behave like sync-v2
class SyncBridgeHathorCapabilitiesTestCase(unittest.SyncBridgeParams, SyncV2HathorCapabilitiesTestCase):
    pass
