from unittest.mock import Mock, patch

import pytest
from twisted.internet.defer import Deferred, TimeoutError
from twisted.python.failure import Failure
from twisted.web.client import Agent

from hathor.conf.get_settings import get_global_settings
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import WhitelistPolicy, parse_whitelist
from hathor.p2p.whitelist_manager import WHITELIST_REQUEST_TIMEOUT
from hathor.simulator import FakeConnection
from hathor_tests import unittest

PEER_A_HEX = '00' * 32
PEER_B_HEX = '11' * 32
PEER_A = PeerId(PEER_A_HEX)
PEER_B = PeerId(PEER_B_HEX)


def test_parse_whitelist_default_policy() -> None:
    text = f'hathor-whitelist\n{PEER_A_HEX}\n'
    peers, policy = parse_whitelist(text)
    assert peers == {PEER_A}
    assert policy == WhitelistPolicy.ONLY_WHITELISTED_PEERS


def test_parse_whitelist_allow_all_policy() -> None:
    text = 'hathor-whitelist\n# policy: allow-all\n'
    peers, policy = parse_whitelist(text)
    assert peers == set()
    assert policy == WhitelistPolicy.ALLOW_ALL


def test_parse_whitelist_only_whitelisted_policy_with_peers() -> None:
    text = f'hathor-whitelist\n# policy: only-whitelisted-peers\n{PEER_A_HEX}\n{PEER_B_HEX}\n'
    peers, policy = parse_whitelist(text)
    assert peers == {PEER_A, PEER_B}
    assert policy == WhitelistPolicy.ONLY_WHITELISTED_PEERS


def test_parse_whitelist_policy_is_case_insensitive() -> None:
    text = 'hathor-whitelist\n# Policy: ALLOW-ALL\n'
    peers, policy = parse_whitelist(text)
    assert peers == set()
    assert policy == WhitelistPolicy.ALLOW_ALL


def test_parse_whitelist_policy_after_peer_id_is_rejected() -> None:
    text = f'hathor-whitelist\n{PEER_A_HEX}\n# policy: allow-all\n'
    with pytest.raises(ValueError, match='before any peer ID'):
        parse_whitelist(text)


def test_parse_whitelist_duplicate_policy_is_rejected() -> None:
    text = 'hathor-whitelist\n# policy: allow-all\n# policy: only-whitelisted-peers\n'
    with pytest.raises(ValueError, match='duplicate policy directive'):
        parse_whitelist(text)


def test_parse_whitelist_invalid_policy_value_is_rejected() -> None:
    text = 'hathor-whitelist\n# policy: bogus\n'
    with pytest.raises(ValueError, match='invalid whitelist policy'):
        parse_whitelist(text)


def test_parse_whitelist_invalid_header_is_rejected() -> None:
    with pytest.raises(ValueError, match='invalid header'):
        parse_whitelist('not-the-header\n')


def test_parse_whitelist_unrelated_comments_do_not_set_policy() -> None:
    text = f'hathor-whitelist\n# node A\n{PEER_A_HEX}\n'
    peers, policy = parse_whitelist(text)
    assert peers == {PEER_A}
    assert policy == WhitelistPolicy.ONLY_WHITELISTED_PEERS


def test_parse_whitelist_allow_all_with_peers_is_rejected() -> None:
    text = f'hathor-whitelist\n# policy: allow-all\n{PEER_A_HEX}\n'
    with pytest.raises(ValueError, match='peer list must be empty'):
        parse_whitelist(text)


def test_parse_whitelist_skips_malformed_peer_ids() -> None:
    text = f'hathor-whitelist\n{PEER_A_HEX}\nnot-a-valid-peer-id\n{PEER_B_HEX}\n'
    peers, policy = parse_whitelist(text)
    assert peers == {PEER_A, PEER_B}
    assert policy == WhitelistPolicy.ONLY_WHITELISTED_PEERS


class WhitelistTestCase(unittest.TestCase):
    def test_whitelist_no_no(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings().model_copy(update={'ENABLE_PEER_WHITELIST': True})

        manager1 = self.create_peer(network)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
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
        self._settings = get_global_settings().model_copy(update={'ENABLE_PEER_WHITELIST': True})

        manager1 = self.create_peer(network)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager1.connections.whitelist.add_peer(manager2.my_peer.id)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    def test_whitelist_allow_all_policy_admits_unlisted_peers(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings().model_copy(update={'ENABLE_PEER_WHITELIST': True})

        manager1 = self.create_peer(network)
        manager2 = self.create_peer(network)

        # Neither peer is in the other's whitelist, but both have ALLOW_ALL active.
        manager1.connections.whitelist.policy = WhitelistPolicy.ALLOW_ALL
        manager2.connections.whitelist.policy = WhitelistPolicy.ALLOW_ALL

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def test_update_cb_updates_policy(self) -> None:
        network = 'testnet'
        manager: HathorManager = self.create_peer(network)
        whitelist = manager.connections.whitelist

        body = b'hathor-whitelist\n# policy: allow-all\n'
        whitelist._update_cb(body)

        assert whitelist.policy == WhitelistPolicy.ALLOW_ALL

    def test_whitelist_yes_yes(self) -> None:
        network = 'testnet'
        self._settings = get_global_settings().model_copy(update={'ENABLE_PEER_WHITELIST': True})

        manager1 = self.create_peer(network)
        self.assertEqual(manager1.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager2 = self.create_peer(network)
        self.assertEqual(manager2.connections.get_enabled_sync_versions(), {SyncVersion.V2})

        manager1.connections.whitelist.add_peer(manager2.my_peer.id)
        manager2.connections.whitelist.add_peer(manager1.my_peer.id)

        conn = FakeConnection(manager1, manager2)
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

        # Run the p2p protocol.
        for _ in range(100):
            conn.run_one_step(debug=True)
            self.clock.advance(0.1)

        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def test_update(self) -> None:
        network = 'testnet'
        manager: HathorManager = self.create_peer(network)
        whitelist = manager.connections.whitelist

        settings_mock = Mock()
        settings_mock.WHITELIST_URL = 'some_url'
        whitelist._settings = settings_mock

        agent_mock = Mock(spec_set=Agent)
        agent_mock.request = Mock()
        whitelist._http_agent = agent_mock

        with (
            patch.object(whitelist, '_update_cb') as _update_cb_mock,
            patch.object(whitelist, '_update_err') as _update_err_mock,
            patch('twisted.web.client.readBody') as read_body_mock
        ):
            # Test success
            agent_mock.request.return_value = Deferred()
            read_body_mock.return_value = b'body'
            d = whitelist.update()
            d.callback(None)

            read_body_mock.assert_called_once_with(None)
            _update_cb_mock.assert_called_once_with(b'body')
            _update_err_mock.assert_not_called()

            read_body_mock.reset_mock()
            _update_cb_mock.reset_mock()
            _update_err_mock.reset_mock()

            # Test request error
            agent_mock.request.return_value = Deferred()
            d = whitelist.update()
            error = Failure('some_error')
            d.errback(error)

            read_body_mock.assert_not_called()
            _update_cb_mock.assert_not_called()
            _update_err_mock.assert_called_once_with(error)

            read_body_mock.reset_mock()
            _update_cb_mock.reset_mock()
            _update_err_mock.reset_mock()

            # Test timeout
            agent_mock.request.return_value = Deferred()
            read_body_mock.return_value = b'body'
            whitelist.update()

            self.clock.advance(WHITELIST_REQUEST_TIMEOUT + 1)

            read_body_mock.assert_not_called()
            _update_cb_mock.assert_not_called()
            _update_err_mock.assert_called_once()
            assert isinstance(_update_err_mock.call_args.args[0].value, TimeoutError)
