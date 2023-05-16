from unittest.mock import patch

from hathor.conf import HathorSettings
from hathor.p2p.sync_version import SyncVersion
from hathor.simulator import FakeConnection
from tests import unittest

settings = HathorSettings()


class WhitelistTestCase(unittest.SyncV1Params, unittest.TestCase):
    @patch('hathor.p2p.states.peer_id.settings', new=settings._replace(ENABLE_PEER_WHITELIST=True))
    def test_sync_v11_whitelist_no_no(self):
        network = 'testnet'

        manager1 = self.create_peer(network)
        self.assertEqual(set(manager1.connections._sync_factories.keys()), {SyncVersion.V1_1})

        manager2 = self.create_peer(network)
        self.assertEqual(set(manager2.connections._sync_factories.keys()), {SyncVersion.V1_1})

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertTrue(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    @patch('hathor.p2p.states.peer_id.settings', new=settings._replace(ENABLE_PEER_WHITELIST=True))
    def test_sync_v11_whitelist_yes_no(self):
        network = 'testnet'

        manager1 = self.create_peer(network)
        self.assertEqual(set(manager1.connections._sync_factories.keys()), {SyncVersion.V1_1})

        manager2 = self.create_peer(network)
        self.assertEqual(set(manager2.connections._sync_factories.keys()), {SyncVersion.V1_1})

        manager1.peers_whitelist.append(manager2.my_peer.id)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    @patch('hathor.p2p.states.peer_id.settings', new=settings._replace(ENABLE_PEER_WHITELIST=True))
    def test_sync_v11_whitelist_yes_yes(self):
        network = 'testnet'

        manager1 = self.create_peer(network)
        self.assertEqual(set(manager1.connections._sync_factories.keys()), {SyncVersion.V1_1})

        manager2 = self.create_peer(network)
        self.assertEqual(set(manager2.connections._sync_factories.keys()), {SyncVersion.V1_1})

        manager1.peers_whitelist.append(manager2.my_peer.id)
        manager2.peers_whitelist.append(manager1.my_peer.id)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)
