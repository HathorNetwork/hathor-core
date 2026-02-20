import tempfile
from typing import Any
from unittest.mock import Mock, patch

from twisted.internet.defer import Deferred, TimeoutError
from twisted.python.failure import Failure
from twisted.web.client import Agent

from hathor.conf.get_settings import get_global_settings
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.whitelist import (
    WHITELIST_REQUEST_TIMEOUT,
    WHITELIST_RETRY_INTERVAL_MAX,
    WHITELIST_RETRY_INTERVAL_MIN,
    WHITELIST_SPEC_DEFAULT,
    WHITELIST_SPEC_DISABLED,
    WHITELIST_SPEC_HATHORLABS,
    WHITELIST_SPEC_NONE,
    FilePeersWhitelist,
    URLPeersWhitelist,
    WhitelistPolicy,
    parse_whitelist_with_policy,
)
from hathor.simulator import FakeConnection
from hathor_tests import unittest


class WhitelistTestCase(unittest.TestCase):
    def test_whitelist_no_no(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings()
        url_1 = 'https://whitelist1.com'
        url_2 = 'https://whitelist2.com'
        manager1 = self.create_peer(network, url_whitelist=url_1)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network, url_whitelist=url_2)
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # Create a dummy peer for both managers to populate their whitelists.
        dummy_manager = self.create_peer(network)
        manager1.connections.peers_whitelist.add_peer(dummy_manager.my_peer.id)
        manager2.connections.peers_whitelist.add_peer(dummy_manager.my_peer.id)

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

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
        url_1 = 'https://whitelist1.com'
        url_2 = 'https://whitelist2.com'
        self._settings = get_global_settings()
        manager1 = self.create_peer(network, url_whitelist=url_1)

        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network, url_whitelist=url_2)
        # Both follow their respective whitelist, although manager1 is not in manager2's whitelist.
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # Whitelist of Manager 2 is empty, which still lets connections happen.
        # We'll create a dummy peer id for manager2 to simulate a whitelist entry.
        dummy_manager = self.create_peer(network)
        manager2.connections.peers_whitelist.add_peer(dummy_manager.my_peer.id)

        # Now, manager2 has a non-empty whitelist, so not having manager1 in it will cause a disconnect.
        manager1.connections.peers_whitelist.add_peer(manager2.my_peer.id)

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

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
        url_1 = 'https://whitelist1.com'
        url_2 = 'https://whitelist2.com'
        manager1 = self.create_peer(network, url_whitelist=url_1)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network, url_whitelist=url_2)
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # Mock Peers Whitelist does not fetch peer Ids from blank url
        self.assertTrue(manager1.connections.peers_whitelist.current_whitelist() == set())
        self.assertTrue(manager2.connections.peers_whitelist.current_whitelist() == set())

        manager1.connections.peers_whitelist.add_peer(manager2.my_peer.id)
        manager2.connections.peers_whitelist.add_peer(manager1.my_peer.id)

        self.assertTrue(len(manager1.connections.peers_whitelist.current_whitelist()) == 1)
        self.assertTrue(len(manager2.connections.peers_whitelist.current_whitelist()) == 1)

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

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

        settings_mock = Mock()
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

    def test_empty_whitelist_blocks_peers(self) -> None:
        """Test that empty whitelist with ONLY_WHITELISTED_PEERS policy blocks peers after grace period.

        With the fix for the empty whitelist policy bug, an empty whitelist with
        restrictive policy should now block all peers (not allow all as before),
        but only after the grace period ends (first successful fetch).
        """
        network = 'testnet'
        self._settings = get_global_settings()
        url_1 = 'https://whitelist1.com'
        url_2 = 'https://whitelist2.com'
        manager1 = self.create_peer(network, url_whitelist=url_1)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network, url_whitelist=url_2)
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        # No peers will be added to the whitelist, so _current is empty.
        # With ONLY_WHITELISTED_PEERS policy, empty whitelist should block all peers after grace period.

        self.assertTrue(len(manager1.connections.peers_whitelist.current_whitelist()) == 0)
        self.assertTrue(len(manager2.connections.peers_whitelist.current_whitelist()) == 0)

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # With empty whitelist and restrictive policy, peers should be blocked
        self.assertTrue(conn.tr1.disconnecting or conn.tr2.disconnecting)


class ParseWhitelistWithPolicyTestCase(unittest.TestCase):
    """Tests for parse_whitelist_with_policy function."""

    def test_parse_allow_all_policy(self) -> None:
        """Test parsing whitelist with allow-all policy."""
        content = """hathor-whitelist
#policy: allow-all
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ALLOW_ALL)
        self.assertEqual(peers, set())

    def test_parse_only_whitelisted_peers_policy(self) -> None:
        """Test parsing whitelist with only-whitelisted-peers policy."""
        content = """hathor-whitelist
#policy: only-whitelisted-peers
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ONLY_WHITELISTED_PEERS)
        self.assertEqual(len(peers), 1)
        self.assertIn(PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'), peers)

    def test_parse_default_policy(self) -> None:
        """Test that default policy is ONLY_WHITELISTED_PEERS when no policy line."""
        content = """hathor-whitelist
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ONLY_WHITELISTED_PEERS)
        self.assertEqual(len(peers), 1)

    def test_parse_policy_with_comments(self) -> None:
        """Test parsing whitelist with policy and comments."""
        content = """hathor-whitelist
# This whitelist allows all peers
#policy: allow-all
# More comments here
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ALLOW_ALL)
        self.assertEqual(peers, set())

    def test_parse_policy_after_peer_raises_error(self) -> None:
        """Test that policy line after peer IDs raises ValueError."""
        content = """hathor-whitelist
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
#policy: allow-all
"""
        with self.assertRaises(ValueError) as context:
            parse_whitelist_with_policy(content)
        self.assertIn('policy must be defined in the header', str(context.exception))

    def test_parse_invalid_policy_uses_default(self) -> None:
        """Test that invalid policy logs a warning and uses the default."""
        content = """hathor-whitelist
#policy: invalid-policy
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ONLY_WHITELISTED_PEERS)
        self.assertEqual(peers, set())

    def test_parse_policy_with_space_after_hash(self) -> None:
        """Test parsing whitelist with '# policy:' (space after #)."""
        content = """hathor-whitelist
# policy: allow-all
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ALLOW_ALL)
        self.assertEqual(len(peers), 1)
        self.assertIn(PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'), peers)

    def test_parse_policy_no_space_after_hash(self) -> None:
        """Test parsing whitelist with '#policy:' (no space after #) still works."""
        content = """hathor-whitelist
#policy: allow-all
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ALLOW_ALL)
        self.assertEqual(peers, set())

    def test_parse_policy_case_insensitive(self) -> None:
        """Test that policy values are case-insensitive."""
        content = """hathor-whitelist
#policy: ALLOW-ALL
"""
        peers, policy = parse_whitelist_with_policy(content)
        self.assertEqual(policy, WhitelistPolicy.ALLOW_ALL)


class WhitelistPolicyBehaviorTestCase(unittest.TestCase):
    """Tests for WhitelistPolicy behavior in PeersWhitelist."""

    def test_is_peer_allowed_with_allow_all(self) -> None:
        """Test that is_peer_allowed returns True with ALLOW_ALL policy after grace period."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Set policy to ALLOW_ALL
        whitelist._policy = WhitelistPolicy.ALLOW_ALL

        # Simulate successful fetch to end grace period
        whitelist._has_successful_fetch = True

        # Even with an empty whitelist, any peer should be allowed with ALLOW_ALL policy
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertTrue(whitelist.is_peer_allowed(random_peer_id))

    def test_is_peer_allowed_with_only_whitelisted_peers(self) -> None:
        """Test that is_peer_allowed checks whitelist with ONLY_WHITELISTED_PEERS policy after grace period."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Ensure policy is ONLY_WHITELISTED_PEERS (default)
        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Simulate a successful fetch to end grace period
        whitelist._has_successful_fetch = True

        # Add a peer to whitelist
        whitelisted_peer_id = PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367')
        whitelist.add_peer(whitelisted_peer_id)

        # Whitelisted peer should be allowed
        self.assertTrue(whitelist.is_peer_allowed(whitelisted_peer_id))

        # Non-whitelisted peer should not be allowed after grace period
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

    def test_policy_method(self) -> None:
        """Test the policy() method returns correct policy."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Default policy
        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Change policy
        whitelist._policy = WhitelistPolicy.ALLOW_ALL
        self.assertEqual(whitelist.policy(), WhitelistPolicy.ALLOW_ALL)


class FilePeersWhitelistTestCase(unittest.TestCase):
    """Tests for FilePeersWhitelist class."""

    def test_file_whitelist_reads_valid_file(self) -> None:
        """Test that FilePeersWhitelist correctly reads a valid whitelist file."""
        content = """hathor-whitelist
#policy: only-whitelisted-peers
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name

        whitelist = FilePeersWhitelist(self.clock, path)

        # Mock deferToThread to call the function directly (synchronously)
        with patch('hathor.p2p.whitelist.file_whitelist.threads.deferToThread') as mock_defer:
            def call_directly(func: Any, *args: Any, **kwargs: Any) -> Deferred[None]:
                d: Deferred[None] = Deferred()
                try:
                    result = func(*args, **kwargs)
                    d.callback(result)
                except Exception as e:
                    d.errback(e)
                return d
            mock_defer.side_effect = call_directly

            whitelist.update()

        # Verify the whitelist was parsed correctly
        self.assertEqual(len(whitelist.current_whitelist()), 2)
        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)
        peer_id = PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367')
        self.assertIn(peer_id, whitelist.current_whitelist())

    def test_file_whitelist_handles_missing_file(self) -> None:
        """Test that FilePeersWhitelist handles missing files gracefully."""
        whitelist = FilePeersWhitelist(self.clock, '/nonexistent/path/whitelist.txt')

        # Mock deferToThread to call the function directly (synchronously)
        with patch('hathor.p2p.whitelist.file_whitelist.threads.deferToThread') as mock_defer:
            def call_directly(func: Any, *args: Any, **kwargs: Any) -> Deferred[None]:
                d: Deferred[None] = Deferred()
                try:
                    result = func(*args, **kwargs)
                    d.callback(result)
                except Exception as e:
                    d.errback(Failure(e))
                return d
            mock_defer.side_effect = call_directly

            whitelist.update()

        # Whitelist should remain empty
        self.assertEqual(len(whitelist.current_whitelist()), 0)
        # Failure counter should be incremented
        self.assertEqual(whitelist._consecutive_failures, 1)

    def test_file_whitelist_handles_permission_error(self) -> None:
        """Test that FilePeersWhitelist handles permission errors gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("hathor-whitelist\n")
            path = f.name

        whitelist = FilePeersWhitelist(self.clock, path)

        # Mock deferToThread to raise PermissionError
        with patch('hathor.p2p.whitelist.file_whitelist.threads.deferToThread') as mock_defer:
            def raise_permission_error(func: Any, *args: Any, **kwargs: Any) -> Deferred[None]:
                d: Deferred[None] = Deferred()
                d.errback(Failure(PermissionError("Permission denied")))
                return d
            mock_defer.side_effect = raise_permission_error

            whitelist.update()

        # Whitelist should remain empty
        self.assertEqual(len(whitelist.current_whitelist()), 0)
        # Failure counter should be incremented
        self.assertEqual(whitelist._consecutive_failures, 1)

    def test_file_whitelist_refresh_returns_deferred(self) -> None:
        """Test that FilePeersWhitelist.refresh() returns a Deferred."""
        content = """hathor-whitelist
#policy: allow-all
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name

        whitelist = FilePeersWhitelist(self.clock, path)
        result = whitelist.refresh()

        self.assertIsInstance(result, Deferred)


class InvalidPeerIdParsingTestCase(unittest.TestCase):
    """Tests for invalid peer ID handling in whitelist parsing."""

    def test_parse_whitelist_with_invalid_hex(self) -> None:
        """Test that invalid hex characters in peer ID are skipped."""
        content = """hathor-whitelist
# Valid peer
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
# Invalid peer (contains 'G')
Gffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
"""
        peers, policy = parse_whitelist_with_policy(content)
        # Only the valid peer should be parsed
        self.assertEqual(len(peers), 1)
        self.assertIn(PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'), peers)

    def test_parse_whitelist_with_short_id(self) -> None:
        """Test that short peer IDs are skipped."""
        content = """hathor-whitelist
# Valid peer
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
# Too short
2ffdfbbfd6d869a0
"""
        peers, policy = parse_whitelist_with_policy(content)
        # Only the valid peer should be parsed
        self.assertEqual(len(peers), 1)

    def test_parse_whitelist_skips_invalid_keeps_valid(self) -> None:
        """Test that invalid peer IDs are skipped while valid ones are kept."""
        content = """hathor-whitelist
# Valid peer 1
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
# Invalid peer
not-a-valid-peer-id
# Valid peer 2
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
# Another invalid one
xyz
"""
        peers, policy = parse_whitelist_with_policy(content)
        # Only the valid peers should be parsed
        self.assertEqual(len(peers), 2)
        self.assertIn(PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'), peers)
        self.assertIn(PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'), peers)


class ExponentialBackoffTestCase(unittest.TestCase):
    """Tests for exponential backoff retry mechanism."""

    def test_url_whitelist_retry_backoff(self) -> None:
        """Test that URL whitelist uses exponential backoff on failures."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        if not isinstance(whitelist, URLPeersWhitelist):
            self.skipTest("Test requires URLPeersWhitelist")

        # Initial state
        self.assertEqual(whitelist._consecutive_failures, 0)

        # Simulate failures
        whitelist._on_update_failure()
        self.assertEqual(whitelist._consecutive_failures, 1)
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN * 2)

        whitelist._on_update_failure()
        self.assertEqual(whitelist._consecutive_failures, 2)
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN * 4)

        whitelist._on_update_failure()
        self.assertEqual(whitelist._consecutive_failures, 3)
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN * 8)

        # Test max cap
        for _ in range(10):
            whitelist._on_update_failure()
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MAX)

        # Test reset on success
        whitelist._on_update_success()
        self.assertEqual(whitelist._consecutive_failures, 0)
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN)

    def test_file_whitelist_retry_backoff(self) -> None:
        """Test that file whitelist uses exponential backoff on failures."""
        whitelist = FilePeersWhitelist(self.clock, '/nonexistent/path.txt')

        # Initial state
        self.assertEqual(whitelist._consecutive_failures, 0)
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN)

        # Simulate failures
        whitelist._on_update_failure()
        self.assertEqual(whitelist._consecutive_failures, 1)
        # After first failure, interval doubles
        self.assertEqual(whitelist._get_retry_interval(), WHITELIST_RETRY_INTERVAL_MIN * 2)


class SysctlWhitelistTestCase(unittest.TestCase):
    """Tests for sysctl whitelist toggle operations."""

    def test_sysctl_toggle_on_without_whitelist_error(self) -> None:
        """Test that set_peers_whitelist handles case when no whitelist is set."""
        network = 'testnet'
        manager = self.create_peer(network)  # no whitelist

        # This should not raise an error
        manager.connections.set_peers_whitelist(None)
        manager.connections.set_peers_whitelist(None)

    def test_sysctl_toggle_disconnects_non_whitelisted(self) -> None:
        """Test that toggling whitelist ON disconnects non-whitelisted peers."""
        network = 'testnet'
        manager1 = self.create_peer(network, url_whitelist='https://whitelist.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist.com')

        # Save whitelist references before suspending
        saved_whitelist1 = manager1.connections.peers_whitelist
        saved_whitelist2 = manager2.connections.peers_whitelist

        # Suspend whitelist during connection setup to allow peers to connect
        manager1.connections.set_peers_whitelist(None)
        manager2.connections.set_peers_whitelist(None)

        # Simulate successful fetches to end grace period (so whitelist rules apply when enabled)
        saved_whitelist1._has_successful_fetch = True
        saved_whitelist2._has_successful_fetch = True

        # Connect the peers
        conn = FakeConnection(manager1, manager2)
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Both should be connected
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Add manager2 to manager1's saved whitelist then re-enable
        saved_whitelist1.add_peer(manager2.my_peer.id)

        # Turn on whitelist on manager1 (should do nothing since manager2 is whitelisted)
        manager1.connections.set_peers_whitelist(saved_whitelist1)

        # Run some steps
        for _ in range(10):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Connections should still be up (manager2 is in manager1's whitelist)
        self.assertFalse(conn.tr1.disconnecting)

    def test_sysctl_swap_to_file(self) -> None:
        """Test swapping from URL whitelist to file whitelist."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')

        # Create a temporary file whitelist
        content = """hathor-whitelist
#policy: allow-all
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name

        # Create a file whitelist
        file_whitelist = FilePeersWhitelist(self.clock, path)

        # Swap whitelists
        manager.connections.set_peers_whitelist(file_whitelist)

        # Verify the swap
        self.assertIsInstance(manager.connections.peers_whitelist, FilePeersWhitelist)

    def test_sysctl_swap_to_url(self) -> None:
        """Test swapping from file whitelist to URL whitelist."""
        # Create a manager with a URL whitelist first
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://oldwhitelist.com')

        # Create a new URL whitelist
        new_url_whitelist = URLPeersWhitelist(self.clock, 'https://newwhitelist.com')

        # Swap whitelists
        manager.connections.set_peers_whitelist(new_url_whitelist)

        # Verify the swap
        self.assertIsInstance(manager.connections.peers_whitelist, URLPeersWhitelist)
        self.assertEqual(manager.connections.peers_whitelist.url(), 'https://newwhitelist.com')


class RaceConditionTestCase(unittest.TestCase):
    """Tests for race condition fixes."""

    def test_race_condition_whitelist_toggle(self) -> None:
        """Test that whitelist_update uses a snapshot to avoid race conditions."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')

        # Create mock connections
        mock_conns = []
        for i in range(5):
            mock_conn = Mock()
            mock_conn.get_peer_id.return_value = PeerId(f'{i:064x}')
            mock_conns.append(mock_conn)

        # Set up the connections set
        manager.connections.connections = set(mock_conns)

        # Add only the first peer to whitelist
        manager.connections.peers_whitelist.add_peer(PeerId(f'{0:064x}'))

        # Simulate a successful whitelist fetch to end grace period
        manager.connections.peers_whitelist._has_successful_fetch = True

        # Trigger disconnect of non-whitelisted peers
        manager.connections._disconnect_non_whitelisted_peers()

        # The first connection should NOT be disconnected (it's whitelisted)
        mock_conns[0].disconnect.assert_not_called()

        # The other connections should be disconnected
        for i in range(1, 5):
            mock_conns[i].disconnect.assert_called_once()


class URLValidationTestCase(unittest.TestCase):
    """Tests for URL validation in URLPeersWhitelist."""

    def test_url_whitelist_none_string(self) -> None:
        """Test that 'none' string URL is converted to None."""
        whitelist = URLPeersWhitelist(self.clock, 'none', mainnet=False)
        self.assertIsNone(whitelist.url())

    def test_url_whitelist_none_string_case_insensitive(self) -> None:
        """Test that 'NONE' string URL is converted to None (case insensitive)."""
        whitelist = URLPeersWhitelist(self.clock, 'NONE', mainnet=False)
        self.assertIsNone(whitelist.url())

    def test_url_whitelist_actual_none(self) -> None:
        """Test that actual None URL works."""
        whitelist = URLPeersWhitelist(self.clock, None, mainnet=False)
        self.assertIsNone(whitelist.url())

    def test_url_whitelist_mainnet_requires_https(self) -> None:
        """Test that mainnet requires HTTPS URLs."""
        with self.assertRaises(ValueError) as context:
            URLPeersWhitelist(self.clock, 'http://whitelist.com', mainnet=True)
        self.assertIn('invalid scheme', str(context.exception))

    def test_url_whitelist_mainnet_accepts_https(self) -> None:
        """Test that mainnet accepts HTTPS URLs."""
        whitelist = URLPeersWhitelist(self.clock, 'https://whitelist.com', mainnet=True)
        self.assertEqual(whitelist.url(), 'https://whitelist.com')

    def test_url_whitelist_none_url_does_not_crash_on_update(self) -> None:
        """Test that URLPeersWhitelist with url=None does not crash on update."""
        whitelist = URLPeersWhitelist(self.clock, 'none', mainnet=False)
        self.assertIsNone(whitelist.url())

        # This should not crash - it should return early
        d = whitelist.update()

        # Verify that no crash occurred and the deferred completed
        self.assertIsNotNone(d)
        # The deferred should complete immediately since URL is None
        # Verify failure count wasn't incremented (no actual update attempted)
        self.assertEqual(whitelist._consecutive_failures, 0)


class EmptyWhitelistPolicyTestCase(unittest.TestCase):
    """Tests for empty whitelist behavior with different policies."""

    def test_empty_whitelist_with_only_whitelisted_peers_blocks_all(self) -> None:
        """Test that empty whitelist with ONLY_WHITELISTED_PEERS policy blocks all peers after grace period."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Ensure whitelist has ONLY_WHITELISTED_PEERS policy (default)
        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Ensure whitelist is empty
        self.assertEqual(len(whitelist.current_whitelist()), 0)

        # Simulate a successful fetch to end grace period
        whitelist._has_successful_fetch = True

        # Any peer should NOT be whitelisted with empty list + restrictive policy after grace period
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

    def test_empty_whitelist_with_allow_all_allows_all(self) -> None:
        """Test that empty whitelist with ALLOW_ALL policy allows all peers after grace period."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Set policy to ALLOW_ALL
        whitelist._policy = WhitelistPolicy.ALLOW_ALL

        # Simulate successful fetch to end grace period
        whitelist._has_successful_fetch = True

        # Ensure whitelist is empty
        self.assertEqual(len(whitelist.current_whitelist()), 0)

        # Any peer should be whitelisted with ALLOW_ALL policy
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertTrue(whitelist.is_peer_allowed(random_peer_id))

    def test_empty_whitelist_blocks_connection_with_restrictive_policy(self) -> None:
        """Test that empty whitelist blocks connections when policy is ONLY_WHITELISTED_PEERS after grace period."""
        network = 'testnet'
        manager1 = self.create_peer(network, url_whitelist='https://whitelist1.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist2.com')

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

        # Verify whitelists are empty
        self.assertEqual(len(manager1.connections.peers_whitelist.current_whitelist()), 0)
        self.assertEqual(len(manager2.connections.peers_whitelist.current_whitelist()), 0)

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Both connections should be disconnected because neither peer is in the other's whitelist
        self.assertTrue(conn.tr1.disconnecting or conn.tr2.disconnecting)


class WhitelistToggleNullPeerIdTestCase(unittest.TestCase):
    """Tests for whitelist_update handling of None peer_id."""

    def test_whitelist_toggle_handles_none_peer_id(self) -> None:
        """Test that whitelist_update handles connections with get_peer_id()=None."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')

        # Create mock connections - some with peer_id, some without
        mock_conns = []

        # Connection with peer_id
        mock_conn_with_id = Mock()
        mock_conn_with_id.get_peer_id.return_value = PeerId(f'{1:064x}')
        mock_conns.append(mock_conn_with_id)

        # Connection without peer_id (still handshaking)
        mock_conn_without_id = Mock()
        mock_conn_without_id.get_peer_id.return_value = None
        mock_conns.append(mock_conn_without_id)

        # Another connection with peer_id
        mock_conn_with_id2 = Mock()
        mock_conn_with_id2.get_peer_id.return_value = PeerId(f'{2:064x}')
        mock_conns.append(mock_conn_with_id2)

        # Set up the connections set
        manager.connections.connections = set(mock_conns)

        # Simulate successful fetch to end grace period
        manager.connections.peers_whitelist._has_successful_fetch = True

        # Don't add any peer to whitelist (empty whitelist with restrictive policy)
        # This should disconnect peers with peer_id but skip those without

        # Trigger disconnect of non-whitelisted peers - this should NOT crash even with None peer_id
        manager.connections._disconnect_non_whitelisted_peers()

        # Connection without peer_id should NOT have disconnect called
        mock_conn_without_id.disconnect.assert_not_called()

        # Connections with peer_id should have disconnect called (they're not in whitelist)
        mock_conn_with_id.disconnect.assert_called_once()
        mock_conn_with_id2.disconnect.assert_called_once()


class WhitelistLifecycleTestCase(unittest.TestCase):
    """Integration tests for full whitelist lifecycle."""

    def test_whitelist_lifecycle_add_peer_then_remove(self) -> None:
        """Test full lifecycle: connect → add to whitelist → enable → remove → disconnect."""
        network = 'testnet'

        # Create two peers with whitelists but suspended initially
        manager1 = self.create_peer(network, url_whitelist='https://whitelist1.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist2.com')

        # Save whitelist references before clearing
        saved_whitelist1 = manager1.connections.peers_whitelist
        saved_whitelist2 = manager2.connections.peers_whitelist

        # Suspend whitelists to allow initial connection
        manager1.connections.set_peers_whitelist(None)
        manager2.connections.set_peers_whitelist(None)

        # Connect the peers
        conn = FakeConnection(manager1, manager2)
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Both should be connected
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)
        self.assertTrue(manager1.connections.is_peer_connected(manager2.my_peer.id))
        self.assertTrue(manager2.connections.is_peer_connected(manager1.my_peer.id))

        # Add each peer to the saved whitelist references
        saved_whitelist1.add_peer(manager2.my_peer.id)
        saved_whitelist2.add_peer(manager1.my_peer.id)

        # Simulate successful fetches to end grace period
        saved_whitelist1._has_successful_fetch = True
        saved_whitelist2._has_successful_fetch = True

        # Re-enable whitelists
        manager1.connections.set_peers_whitelist(saved_whitelist1)
        manager2.connections.set_peers_whitelist(saved_whitelist2)

        # Run some steps - connections should remain up (peers are whitelisted)
        for _ in range(10):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Now simulate removing manager2 from manager1's whitelist
        # Create a new whitelist without manager2
        manager1.connections.peers_whitelist._current = set()

        # Trigger disconnection of non-whitelisted peers
        manager1.connections._disconnect_non_whitelisted_peers()

        # manager2 should be disconnected from manager1's perspective
        # (manager1 initiated the disconnect)
        self.assertTrue(conn.tr1.disconnecting or conn.tr2.disconnecting)

    def test_whitelist_policy_change_affects_connections(self) -> None:
        """Test that changing whitelist policy affects existing connections."""
        network = 'testnet'

        manager1 = self.create_peer(network, url_whitelist='https://whitelist1.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist2.com')

        # Set policy to ALLOW_ALL so connections work even with empty whitelist
        manager1.connections.peers_whitelist._policy = WhitelistPolicy.ALLOW_ALL
        manager2.connections.peers_whitelist._policy = WhitelistPolicy.ALLOW_ALL

        # Simulate successful fetches to end grace period
        manager1.connections.peers_whitelist._has_successful_fetch = True
        manager2.connections.peers_whitelist._has_successful_fetch = True

        # Connect the peers - should work with ALLOW_ALL policy
        conn = FakeConnection(manager1, manager2)
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Both should be connected
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Change policy to ONLY_WHITELISTED_PEERS (whitelist is still empty)
        manager1.connections.peers_whitelist._policy = WhitelistPolicy.ONLY_WHITELISTED_PEERS

        # Trigger disconnect of non-whitelisted peers
        manager1.connections._disconnect_non_whitelisted_peers()

        # manager2 should be disconnected (not in whitelist with restrictive policy)
        self.assertTrue(conn.tr1.disconnecting or conn.tr2.disconnecting)

    def test_whitelist_source_method(self) -> None:
        """Test that source() method returns correct values for different whitelist types."""
        # Test URLPeersWhitelist
        url_whitelist = URLPeersWhitelist(self.clock, 'https://example.com/whitelist', mainnet=False)
        self.assertEqual(url_whitelist.source(), 'https://example.com/whitelist')

        # Test URLPeersWhitelist with None URL
        none_whitelist = URLPeersWhitelist(self.clock, 'none', mainnet=False)
        self.assertIsNone(none_whitelist.source())

        # Test FilePeersWhitelist
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("hathor-whitelist\n#policy: allow-all\n")
            f.flush()
            path = f.name

        file_whitelist = FilePeersWhitelist(self.clock, path)
        self.assertEqual(file_whitelist.source(), path)


class GracePeriodTestCase(unittest.TestCase):
    """Tests for grace period behavior before first successful whitelist fetch."""

    def test_grace_period_rejects_non_bootstrap_peers_before_first_fetch(self) -> None:
        """Test that non-bootstrap peers are rejected before first successful whitelist fetch."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Verify initial state: no successful fetch yet
        self.assertFalse(whitelist._has_successful_fetch)

        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Random peers should NOT be allowed during grace period (only bootstrap peers allowed)
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

    def test_grace_period_allows_bootstrap_peers_before_first_fetch(self) -> None:
        """Test that bootstrap peers are allowed before first successful whitelist fetch."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Verify initial state: no successful fetch yet
        self.assertFalse(whitelist._has_successful_fetch)

        self.assertEqual(whitelist.policy(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Register a bootstrap peer
        bootstrap_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        whitelist.add_bootstrap_peer(bootstrap_peer_id)

        # Bootstrap peer should be allowed during grace period
        self.assertTrue(whitelist.is_peer_allowed(bootstrap_peer_id))

        # Non-bootstrap peer should still be rejected
        random_peer_id = PeerId('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

    def test_grace_period_ends_after_successful_fetch(self) -> None:
        """Test that grace period ends after first successful whitelist fetch."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Verify initial state: no successful fetch yet
        self.assertFalse(whitelist._has_successful_fetch)

        # Simulate a successful whitelist update
        whitelisted_peer_id = PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367')
        whitelist._apply_whitelist_update({whitelisted_peer_id}, WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Verify grace period has ended
        self.assertTrue(whitelist._has_successful_fetch)

        # Now the whitelist should enforce - whitelisted peer is allowed
        self.assertTrue(whitelist.is_peer_allowed(whitelisted_peer_id))

        # Non-whitelisted peer should be blocked after grace period
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

    def test_bootstrap_peer_allowed_during_grace_period_but_normal_rules_after(self) -> None:
        """Test that bootstrap peers follow normal whitelist rules after successful fetch."""
        network = 'testnet'
        manager = self.create_peer(network, url_whitelist='https://whitelist.com')
        whitelist = manager.connections.peers_whitelist

        # Verify initial state: no successful fetch yet
        self.assertFalse(whitelist._has_successful_fetch)

        # Register a bootstrap peer
        bootstrap_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        whitelist.add_bootstrap_peer(bootstrap_peer_id)

        # Bootstrap peer should be allowed during grace period
        self.assertTrue(whitelist.is_peer_allowed(bootstrap_peer_id))

        # Simulate a successful whitelist update that does NOT include the bootstrap peer
        other_peer_id = PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367')
        whitelist._apply_whitelist_update({other_peer_id}, WhitelistPolicy.ONLY_WHITELISTED_PEERS)

        # Verify grace period has ended
        self.assertTrue(whitelist._has_successful_fetch)

        # Bootstrap peer should NOT be allowed anymore (not in whitelist)
        self.assertFalse(whitelist.is_peer_allowed(bootstrap_peer_id))

        # Peer in whitelist should be allowed
        self.assertTrue(whitelist.is_peer_allowed(other_peer_id))

    def test_grace_period_connections_rejected_without_bootstrap(self) -> None:
        """Test that connections are rejected during grace period without bootstrap registration."""
        network = 'testnet'
        manager1 = self.create_peer(network, url_whitelist='https://whitelist1.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist2.com')

        # Verify both whitelists have not had successful fetches
        self.assertFalse(manager1.connections.peers_whitelist._has_successful_fetch)
        self.assertFalse(manager2.connections.peers_whitelist._has_successful_fetch)

        # Whitelists are empty and no bootstrap peers registered
        self.assertEqual(len(manager1.connections.peers_whitelist.current_whitelist()), 0)
        self.assertEqual(len(manager2.connections.peers_whitelist.current_whitelist()), 0)

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # At least one connection should be rejected during grace period (no bootstrap peers)
        self.assertTrue(conn.tr1.disconnecting or conn.tr2.disconnecting)

    def test_grace_period_connections_allowed_with_bootstrap(self) -> None:
        """Test that connections are allowed during grace period when peers are registered as bootstrap."""
        network = 'testnet'
        manager1 = self.create_peer(network, url_whitelist='https://whitelist1.com')
        manager2 = self.create_peer(network, url_whitelist='https://whitelist2.com')

        # Verify both whitelists have not had successful fetches
        self.assertFalse(manager1.connections.peers_whitelist._has_successful_fetch)
        self.assertFalse(manager2.connections.peers_whitelist._has_successful_fetch)

        # Register each peer as a bootstrap peer on the other's whitelist
        manager1.connections.peers_whitelist.add_bootstrap_peer(manager2.my_peer.id)
        manager2.connections.peers_whitelist.add_bootstrap_peer(manager1.my_peer.id)

        conn = FakeConnection(manager1, manager2)

        # Run the p2p protocol
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Both connections should remain up during grace period (peers are registered as bootstrap)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def test_grace_period_flag_persists_through_failures(self) -> None:
        """Test that grace period flag is NOT set on update failures."""
        whitelist = URLPeersWhitelist(self.clock, 'https://whitelist.com', mainnet=False)

        # Initial state: no successful fetch
        self.assertFalse(whitelist._has_successful_fetch)

        # Simulate failures
        whitelist._on_update_failure()
        self.assertFalse(whitelist._has_successful_fetch)

        whitelist._on_update_failure()
        self.assertFalse(whitelist._has_successful_fetch)

        # Only successful update should set the flag
        whitelist._apply_whitelist_update(set(), WhitelistPolicy.ONLY_WHITELISTED_PEERS)
        self.assertTrue(whitelist._has_successful_fetch)

    def test_file_whitelist_grace_period(self) -> None:
        """Test that file whitelist also has grace period behavior."""
        content = """hathor-whitelist
#policy: only-whitelisted-peers
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            path = f.name

        whitelist = FilePeersWhitelist(self.clock, path)

        # Initial state: no successful fetch
        self.assertFalse(whitelist._has_successful_fetch)

        # During grace period, non-bootstrap peers should NOT be allowed
        random_peer_id = PeerId('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

        # But bootstrap peers should be allowed
        bootstrap_peer_id = PeerId('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
        whitelist.add_bootstrap_peer(bootstrap_peer_id)
        self.assertTrue(whitelist.is_peer_allowed(bootstrap_peer_id))

        # Perform an update
        with patch('hathor.p2p.whitelist.file_whitelist.threads.deferToThread') as mock_defer:
            def call_directly(func: Any, *args: Any, **kwargs: Any) -> Deferred[None]:
                d: Deferred[None] = Deferred()
                try:
                    result = func(*args, **kwargs)
                    d.callback(result)
                except Exception as e:
                    d.errback(e)
                return d
            mock_defer.side_effect = call_directly
            whitelist.update()

        # After successful fetch, grace period ends
        self.assertTrue(whitelist._has_successful_fetch)

        # Now the random peer should not be allowed
        self.assertFalse(whitelist.is_peer_allowed(random_peer_id))

        # Bootstrap peer should also NOT be allowed anymore (not in whitelist)
        self.assertFalse(whitelist.is_peer_allowed(bootstrap_peer_id))

        # But the whitelisted peer should be allowed
        whitelisted_peer_id = PeerId('2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367')
        self.assertTrue(whitelist.is_peer_allowed(whitelisted_peer_id))


class WhitelistSpecConstantsTestCase(unittest.TestCase):
    """Tests for whitelist specification constants."""

    def test_whitelist_spec_constants_values(self) -> None:
        """Test that whitelist spec constants have expected values."""
        self.assertEqual(WHITELIST_SPEC_DEFAULT, 'default')
        self.assertEqual(WHITELIST_SPEC_HATHORLABS, 'hathorlabs')
        self.assertEqual(WHITELIST_SPEC_NONE, 'none')
        self.assertEqual(WHITELIST_SPEC_DISABLED, 'disabled')
