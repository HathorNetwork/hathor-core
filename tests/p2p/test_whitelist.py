from unittest.mock import Mock, patch

from twisted.internet.defer import Deferred, TimeoutError
from twisted.python.failure import Failure
from twisted.web.client import Agent

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.manager import HathorManager
from hathor.p2p.peers_whitelist import WHITELIST_REQUEST_TIMEOUT, URLPeersWhitelist
from hathor.p2p.sync_version import SyncVersion
from hathor.simulator import FakeConnection
from tests import unittest


class WhitelistTestCase(unittest.TestCase):
    def test_whitelist_no_no(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings()

        manager1 = self.create_peer(network)
        manager1.connections.peers_whitelist._following_wl = True
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
        manager2.connections.peers_whitelist._following_wl = False
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertTrue(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    def test_whitelist_yes_no(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings()
        manager1 = self.create_peer(network)
        manager1.connections.peers_whitelist.follow_wl()

        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
        # Both follow their respective whitelist, although manager1 is not in manager2's whitelist.
        manager2.connections.peers_whitelist.follow_wl()
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # Whitelist of Manager 2 is empty, which still lets connections happen.
        # We'll create a dummy peer id for manager2 to simulate a whitelist entry.
        dummy_manager = self.create_peer(network)
        manager2.connections.peers_whitelist._current.add(dummy_manager.my_peer.id)

        # Now, manager2 has a non-empty whitelist, so not having manager1 in it will cause a disconnect.
        manager1.connections.peers_whitelist._current.add(manager2.my_peer.id)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    def test_whitelist_yes_yes(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings()

        manager1 = self.create_peer(network)
        manager1.connections.peers_whitelist.follow_wl()
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
        manager2.connections.peers_whitelist.follow_wl()
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # Mock Peers Whitelist does not fetch peer Ids from blank url
        self.assertTrue(manager1.connections.peers_whitelist._current == set())
        self.assertTrue(manager2.connections.peers_whitelist._current == set())

        manager1.connections.peers_whitelist._current.add(manager2.my_peer.id)
        manager2.connections.peers_whitelist._current.add(manager1.my_peer.id)

        self.assertTrue(len(manager1.connections.peers_whitelist._current) == 1)
        self.assertTrue(len(manager2.connections.peers_whitelist._current) == 1)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def test_update_whitelist(self) -> None:
        network = 'testnet'
        manager: HathorManager = self.create_peer(network)
        connections_manager = manager.connections

        settings_mock = Mock(spec_set=HathorSettings)
        settings_mock.WHITELIST_URL = 'https://something.com'
        connections_manager._settings = settings_mock

        agent_mock = Mock(spec_set=Agent)
        agent_mock.request = Mock()
        if type(connections_manager.peers_whitelist) is not URLPeersWhitelist:
            return
        connections_manager.peers_whitelist._http_agent = agent_mock

        with (
            patch.object(connections_manager.peers_whitelist, '_update_whitelist_cb') as _update_whitelist_cb_mock,
            patch.object(connections_manager.peers_whitelist, '_update_whitelist_err') as _update_whitelist_err_mock,
            patch('twisted.web.client.readBody') as read_body_mock
        ):
            # Test success
            agent_mock.request.return_value = Deferred()
            read_body_mock.return_value = b'body'
            d = connections_manager.peers_whitelist.update()
            d.callback(None)

            read_body_mock.assert_called_once_with(None)
            _update_whitelist_cb_mock.assert_called_once_with(b'body')
            _update_whitelist_err_mock.assert_not_called()

            read_body_mock.reset_mock()
            _update_whitelist_cb_mock.reset_mock()
            _update_whitelist_err_mock.reset_mock()

            # Test request error
            agent_mock.request.return_value = Deferred()
            d = connections_manager.peers_whitelist.update()
            error = Failure('some_error')
            d.errback(error)

            read_body_mock.assert_not_called()
            _update_whitelist_cb_mock.assert_not_called()
            _update_whitelist_err_mock.assert_called_once_with(error)

            read_body_mock.reset_mock()
            _update_whitelist_cb_mock.reset_mock()
            _update_whitelist_err_mock.reset_mock()

            # Test timeout
            agent_mock.request.return_value = Deferred()
            read_body_mock.return_value = b'body'
            connections_manager.peers_whitelist.update()

            self.clock.advance(WHITELIST_REQUEST_TIMEOUT + 1)

            read_body_mock.assert_not_called()
            _update_whitelist_cb_mock.assert_not_called()
            _update_whitelist_err_mock.assert_called_once()
            # Check final instance
            assert isinstance(_update_whitelist_err_mock.call_args.args[0].value, TimeoutError)

    def test_no_whitelist_but_follow(self) -> None:
        pass

    def test_whitelist_no_follow(self) -> None:
        pass

    def test_no_whitelist_unfollow(self) -> None:
        pass