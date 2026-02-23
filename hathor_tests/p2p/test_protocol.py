import json
from typing import Optional
from unittest.mock import Mock, patch

import pytest
from twisted.internet import defer
from twisted.internet.address import IPv4Address
from twisted.internet.protocol import Protocol
from twisted.python.failure import Failure

from hathor.manager import HathorManager
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.protocol import HathorLineReceiver, HathorProtocol
from hathor.simulator import FakeConnection
from hathor.util import json_dumps, json_loadb
from hathor_tests import unittest


class HathorProtocolTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.network = 'testnet'
        self.peer1 = PrivatePeer.auto_generated()
        self.peer2 = PrivatePeer.auto_generated()
        self.manager1 = self.create_peer(self.network, peer=self.peer1)
        self.manager2 = self.create_peer(self.network, peer=self.peer2)
        self.conn = FakeConnection(self.manager1, self.manager2)

    def assertAndStepConn(self, conn: FakeConnection, regex1: bytes, regex2: Optional[bytes] = None) -> None:
        """If only one regex is given it is tested on both cons, if two are given they'll be used respectively."""
        if regex2 is None:
            regex2 = regex1
        self.assertRegex(conn.peek_tr1_value(), regex1)
        self.assertRegex(conn.peek_tr2_value(), regex2)
        conn.run_one_step()

    def assertIsConnected(self, conn: FakeConnection | None = None) -> None:
        if conn is None:
            conn = self.conn
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def assertIsNotConnected(self, conn: FakeConnection | None = None) -> None:
        if conn is None:
            conn = self.conn
        self.assertTrue(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    def _send_cmd(self, proto: Protocol, cmd: str, payload: str | None = None) -> None:
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        proto.dataReceived(line.encode('utf-8'))

    def _check_result_only_cmd(self, result: bytes, expected_cmd: bytes) -> None:
        cmd_list = []
        for line in result.split(b'\r\n'):
            cmd, _, _ = line.partition(b' ')
            cmd_list.append(cmd)
        self.assertIn(expected_cmd, cmd_list)

    def _check_cmd_and_value(self, result: bytes, expected: tuple[bytes, bytes]) -> None:
        result_list = []
        for line in result.split(b'\r\n'):
            cmd, _, data = line.partition(b' ')
            result_list.append((cmd, data))
        self.assertIn(expected, result_list)

    def test_on_connect(self) -> None:
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'HELLO')

    def test_peer_with_entrypoint(self) -> None:
        entrypoint_str = 'tcp://192.168.1.1:54321'
        entrypoint = PeerAddress.parse(entrypoint_str)
        self.peer1.info.entrypoints.add(entrypoint)
        self.peer2.info.entrypoints.add(entrypoint)
        self.conn.run_one_step()  # HELLO

        msg1 = self.conn.peek_tr1_value()
        cmd1, val1 = msg1.split(b' ', 1)
        data1 = json_loadb(val1)
        self.assertEqual(cmd1, b'PEER-ID')
        self.assertEqual(data1['entrypoints'], [entrypoint_str])

        msg2 = self.conn.peek_tr2_value()
        cmd2, val2 = msg2.split(b' ', 1)
        data2 = json_loadb(val2)
        self.assertEqual(cmd2, b'PEER-ID')
        self.assertEqual(data2['entrypoints'], [entrypoint_str])

    def test_invalid_command(self) -> None:
        self._send_cmd(self.conn.proto1, 'INVALID-CMD')
        self.conn.proto1.state.handle_error('')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_rate_limit(self) -> None:
        hits = 1
        window = 60

        self.conn.proto1.ratelimit.set_limit(HathorProtocol.RateLimitKeys.GLOBAL, hits, window)
        # first will be OK and reach the hits limit per window
        self.conn.run_one_step()  # HELLO
        # second will fail and be throttled
        self.conn.run_one_step()  # PEER-ID

        self._check_cmd_and_value(
            self.conn.peek_tr1_value(),
            (b'THROTTLE', 'global At most {} hits every {} seconds'.format(hits, window).encode('utf-8')),
        )

        self.conn.proto1.state.handle_throttle(b'')

        # Test empty disconnect
        self.conn.proto1.state = None
        with pytest.raises(AssertionError):
            # TODO: This raises because we are trying to disconnect a protocol with no state, but it's not possible
            #  for a protocol to have no state after it's handshaking. We have to update this when we introduce the
            #  new non-None initial state for protocols.
            self.conn.proto1.on_disconnect(Failure(Exception()))

    def test_invalid_size(self) -> None:
        self.conn.tr1.clear()
        cmd = b'HELLO '
        max_payload_bytes = HathorLineReceiver.MAX_LENGTH - len(cmd)
        line_length_exceeded_wrapped = Mock(wraps=self.conn.proto1.lineLengthExceeded)

        biggest_valid_payload = bytes([1] * max_payload_bytes)
        line = cmd + biggest_valid_payload + b'\r\n'

        with patch.object(self.conn.proto1, 'lineLengthExceeded', line_length_exceeded_wrapped):
            self.conn.proto1.dataReceived(line)

        line_length_exceeded_wrapped.assert_not_called()
        line_length_exceeded_wrapped.reset_mock()

        smallest_invalid_payload = bytes([1] * (max_payload_bytes + 1))
        line = cmd + smallest_invalid_payload + b'\r\n'

        with patch.object(self.conn.proto1, 'lineLengthExceeded', line_length_exceeded_wrapped):
            self.conn.proto1.dataReceived(line)

        line_length_exceeded_wrapped.assert_called_once()
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_payload(self) -> None:
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'PEERS', 'abc')
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEERS" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello1(self) -> None:
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello2(self) -> None:
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO', 'invalid_payload')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello3(self) -> None:
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO', '{}')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello4(self) -> None:
        self.conn.tr1.clear()
        self._send_cmd(
            self.conn.proto1,
            'HELLO',
            '{"app": 0, "remote_address": 1, "network": 2, "genesis_hash": "123", "settings_hash": "456"}'
        )
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello5(self) -> None:
        # hello with clocks too far apart
        self.conn.tr1.clear()
        data = self.conn.proto2.state._get_hello_data()
        data['timestamp'] = data['timestamp'] + self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED/2 + 1
        self._send_cmd(
            self.conn.proto1,
            'HELLO',
            json_dumps(data),
        )
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_valid_hello(self) -> None:
        self.conn.run_one_step()  # HELLO
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEER-ID')
        self.assertFalse(self.conn.tr1.disconnecting)
        self.assertFalse(self.conn.tr2.disconnecting)

    def test_hello_without_ipv6_capability(self) -> None:
        """Tests the connection between peers with and without the IPV6 capability.
           Expected behavior: the entrypoint with IPV6 is not relayed.
        """
        network = 'testnet'
        manager1 = self.create_peer(
            network,
            peer=self.peer1,
            capabilities=[self._settings.CAPABILITY_IPV6, self._settings.CAPABILITY_SYNC_VERSION]
        )
        manager2 = self.create_peer(
            network,
            peer=self.peer2,
            capabilities=[self._settings.CAPABILITY_SYNC_VERSION]
        )

        port1 = FakeConnection._get_port(manager1)
        port2 = FakeConnection._get_port(manager2)

        addr1 = IPv4Address('TCP', '192.168.1.1', port1)
        addr2 = IPv4Address('TCP', '192.168.1.1', port2)

        entrypoint_1_ipv6 = PeerEndpoint.parse('tcp://[::1]:54321')
        entrypoint_1_ipv4 = PeerEndpoint.parse(f'tcp://192.168.1.1:{port1}')
        entrypoint_2_ipv4 = PeerEndpoint.parse(f'tcp://192.168.1.1:{port2}')

        self.peer1.info.entrypoints.add(entrypoint_1_ipv6.addr)
        self.peer1.info.entrypoints.add(entrypoint_1_ipv4.addr)
        self.peer2.info.entrypoints.add(entrypoint_2_ipv4.addr)

        conn = FakeConnection(manager1, manager2, addr1=addr1, addr2=addr2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID

        self.assertEqual(len(conn.proto1.peer.info.entrypoints), 1)
        self.assertEqual(len(conn.proto2.peer.info.entrypoints), 1)
        self.assertEqual(next(iter(conn.proto1.peer.info.entrypoints)).host, '192.168.1.1')
        self.assertEqual(next(iter(conn.proto2.peer.info.entrypoints)).host, '192.168.1.1')

    def test_hello_with_ipv6_capability(self) -> None:
        """Tests the connection between peers with the IPV6 capability.
           Expected behavior: the entrypoint with IPV6 is relayed.
        """
        network = 'testnet'
        manager1 = self.create_peer(
            network,
            peer=self.peer1,
            capabilities=[self._settings.CAPABILITY_IPV6, self._settings.CAPABILITY_SYNC_VERSION]
        )
        manager2 = self.create_peer(
            network,
            peer=self.peer2,
            capabilities=[self._settings.CAPABILITY_IPV6, self._settings.CAPABILITY_SYNC_VERSION]
        )

        port1 = FakeConnection._get_port(manager1)
        port2 = FakeConnection._get_port(manager2)

        addr1 = IPv4Address('TCP', '192.168.1.1', port1)
        addr2 = IPv4Address('TCP', '192.168.1.1', port2)

        entrypoint_1_ipv6 = PeerEndpoint.parse('tcp://[::1]:54321')
        entrypoint_1_ipv4 = PeerEndpoint.parse(f'tcp://192.168.1.1:{port1}')
        entrypoint_2_ipv4 = PeerEndpoint.parse(f'tcp://192.168.1.1:{port2}')

        self.peer1.info.entrypoints.add(entrypoint_1_ipv6.addr)
        self.peer1.info.entrypoints.add(entrypoint_1_ipv4.addr)
        self.peer2.info.entrypoints.add(entrypoint_2_ipv4.addr)

        conn = FakeConnection(manager1, manager2, addr1=addr1, addr2=addr2)

        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID

        self.assertEqual(len(conn.proto1.peer.info.entrypoints), 1)
        self.assertEqual(len(conn.proto2.peer.info.entrypoints), 2)
        self.assertTrue('::1' in map(lambda x: x.host, conn.proto2.peer.info.entrypoints))
        self.assertTrue('192.168.1.1' in map(lambda x: x.host, conn.proto2.peer.info.entrypoints))
        self.assertEqual(next(iter(conn.proto1.peer.info.entrypoints)).host, '192.168.1.1')

    def test_invalid_duplicate_addr(self) -> None:
        """
        We try to connect to an already connected entrypoint in each state,
        and it should never add the new connection to connecting_outbound_peers.
        """
        # We also specifically compare localhost with 127.0.0.1, because they are considered the same.
        assert self.conn.addr2.type == 'TCP' and self.conn.addr2.host == '127.0.0.1'
        entrypoint = PeerEndpoint.parse(f'tcp://localhost:{self.conn.addr2.port}')

        self.manager1.connections.connect_to(entrypoint)
        assert self.manager1.connections._connections.connecting_outbound_peers() == set()
        assert self.manager1.connections._connections.handshaking_peers() == {self.conn.peer_addr2: self.conn.proto1}
        assert self.manager1.connections._connections.ready_peers() == {}
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'HELLO')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'HELLO')

        self.conn.run_one_step()  # HELLO
        self.manager1.connections.connect_to(entrypoint)
        assert self.manager1.connections._connections.connecting_outbound_peers() == set()
        assert self.manager1.connections._connections.handshaking_peers() == {self.conn.peer_addr2: self.conn.proto1}
        assert self.manager1.connections._connections.ready_peers() == {}
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEER-ID')

        self.conn.run_one_step()  # PEER-ID
        self.manager1.connections.connect_to(entrypoint)
        assert self.manager1.connections._connections.connecting_outbound_peers() == set()
        assert self.manager1.connections._connections.handshaking_peers() == {self.conn.peer_addr2: self.conn.proto1}
        assert self.manager1.connections._connections.ready_peers() == {}
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'READY')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'READY')

        self.conn.run_one_step()  # READY
        self.manager1.connections.connect_to(entrypoint)
        assert self.manager1.connections._connections.connecting_outbound_peers() == set()
        assert self.manager1.connections._connections.handshaking_peers() == {}
        assert self.manager1.connections._connections.ready_peers() == {self.conn.peer_addr2: self.conn.proto1}

    def test_invalid_same_peer_id(self) -> None:
        manager3 = self.create_peer(self.network, peer=self.peer1)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        self._check_result_only_cmd(conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)

    def test_invalid_same_peer_id2(self) -> None:
        """
        We connect nodes 1-2 and 1-3. Nodes 2 and 3 have the same peer_id. The connections
        are established simultaneously, so we do not detect a peer id duplication in PEER_ID
        state, only on READY state.
        """
        # Disable idle timeout before creating any new peer because self.create_peer(...)
        # runs the main loop.
        self.conn.disable_idle_timeout()
        # Create new peer and disable idle timeout.
        manager3 = self.create_peer(self.network, peer=self.peer2)
        conn = FakeConnection(manager3, self.manager1)
        # Disable idle timeout.
        conn.disable_idle_timeout()
        # HELLO
        self.assertEqual(self.conn.peek_tr1_value().split()[0], b'HELLO')
        self.assertEqual(self.conn.peek_tr2_value().split()[0], b'HELLO')
        self.assertEqual(conn.peek_tr1_value().split()[0],      b'HELLO')
        self.assertEqual(conn.peek_tr2_value().split()[0],      b'HELLO')
        self.conn.run_one_step()
        conn.run_one_step()
        # PEER-ID
        self.assertEqual(self.conn.peek_tr1_value().split()[0], b'PEER-ID')
        self.assertEqual(self.conn.peek_tr2_value().split()[0], b'PEER-ID')
        self.assertEqual(conn.peek_tr1_value().split()[0],      b'PEER-ID')
        self.assertEqual(conn.peek_tr2_value().split()[0],      b'PEER-ID')
        self.conn.run_one_step()
        conn.run_one_step()
        # READY
        self.assertEqual(self.conn.peek_tr1_value().split()[0], b'READY')
        self.assertEqual(self.conn.peek_tr2_value().split()[0], b'READY')
        self.assertEqual(conn.peek_tr1_value().split()[0],      b'READY')
        self.assertEqual(conn.peek_tr2_value().split()[0],      b'READY')
        self.conn.run_one_step()
        conn.run_one_step()
        # continue until messages stop
        self.conn.run_until_empty()
        conn.run_until_empty()
        self.run_to_completion()
        # one of the peers will close the connection. We don't know which one, as it depends
        # on the peer ids

        if bytes(self.peer1.id) > bytes(self.peer2.id):
            tr_dead = self.conn.tr1
            tr_dead_value = self.conn.peek_tr1_value()
            proto_alive = conn.proto2
            conn_alive = conn
        else:
            tr_dead = conn.tr2
            tr_dead_value = conn.peek_tr2_value()
            proto_alive = self.conn.proto1
            conn_alive = self.conn

        self._check_result_only_cmd(tr_dead_value, b'ERROR')
        # at this point, the connection must be closing as the error was detected on READY state
        self.assertTrue(tr_dead.disconnecting)
        # check ready_peers
        ready_peers = list(self.manager1.connections.iter_ready_connections())
        self.assertEquals(1, len(ready_peers))
        self.assertEquals(ready_peers[0], proto_alive)
        # connection is still up
        self.assertIsConnected(conn_alive)

    def test_invalid_peer_id1(self) -> None:
        """Test no payload"""
        self.conn.run_one_step()
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'PEER-ID')
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEER-ID" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_peer_id2(self) -> None:
        """Test invalid json payload"""
        self.conn.run_one_step()
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'PEER-ID', 'invalid_payload')
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEER-ID" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_peer_id3(self) -> None:
        """Test empty payload"""
        self.conn.run_one_step()
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'PEER-ID', '{}')
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEER-ID" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_peer_id4(self) -> None:
        """Test payload with missing property"""
        self.conn.run_one_step()
        self.conn.tr1.clear()
        data = self.conn.proto2.state._get_peer_id_data()
        del data['pubKey']
        self._send_cmd(
            self.conn.proto1,
            'PEER-ID',
            json.dumps(data)
        )
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEER-ID" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_peer_id5(self) -> None:
        """Test payload with peer id not matching public key"""
        self.conn.run_one_step()
        self.conn.tr1.clear()
        data = self.conn.proto2.state._get_peer_id_data()
        new_peer = PrivatePeer.auto_generated()
        data['id'] = str(new_peer.id)
        self._send_cmd(
            self.conn.proto1,
            'PEER-ID',
            json.dumps(data)
        )
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "PEER-ID" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_valid_peer_id(self) -> None:
        self.conn.run_one_step()
        self.conn.run_one_step()
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'READY')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'READY')
        self.assertFalse(self.conn.tr1.disconnecting)
        self.assertFalse(self.conn.tr2.disconnecting)

    def test_invalid_different_network(self) -> None:
        manager3 = self.create_peer(network='mainnet')
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        self._check_result_only_cmd(conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)
        conn.run_one_step()  # ERROR

    def test_send_invalid_unicode(self) -> None:
        # \xff is an invalid unicode.
        self.conn.proto1.dataReceived(b'\xff\r\n')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_on_disconnect(self) -> None:
        self.assertIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())
        self.conn.disconnect(Failure(Exception('testing')))
        self.assertNotIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())

    def test_on_disconnect_after_hello(self) -> None:
        self.conn.run_one_step()  # HELLO
        self.assertIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())
        self.conn.disconnect(Failure(Exception('testing')))
        self.assertNotIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())

    def test_on_disconnect_after_peer(self) -> None:
        self.conn.run_one_step()  # HELLO
        self.assertIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())
        # No peer id in the peer_storage (known_peers)
        self.assertNotIn(self.peer2.id, self.manager1.connections.verified_peer_storage)
        # The peer READY now depends on a message exchange from both peers, so we need one more step
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.assertIn(self.conn.proto1, self.manager1.connections.iter_ready_connections())
        # Peer id 2 in the peer_storage (known_peers) after connection
        self.assertIn(self.peer2.id, self.manager1.connections.verified_peer_storage)
        self.assertNotIn(self.conn.proto1, self.manager1.connections.iter_handshaking_peers())
        self.conn.disconnect(Failure(Exception('testing')))
        # Peer id 2 in the peer_storage (known_peers) after disconnection but before looping call
        self.assertIn(self.peer2.id, self.manager1.connections.verified_peer_storage)
        self.assertNotIn(self.conn.proto1, self.manager1.connections.iter_ready_connections())

        self.clock.advance(10)
        # Peer id 2 removed from peer_storage (known_peers) after disconnection and after looping call
        self.assertNotIn(self.peer2.id, self.manager1.connections.verified_peer_storage)

    def test_idle_connection(self) -> None:
        self.clock.advance(self._settings.PEER_IDLE_TIMEOUT - 10)
        self.assertIsConnected(self.conn)
        self.clock.advance(15)
        self.assertIsNotConnected(self.conn)

    def test_invalid_expected_peer_id(self) -> None:
        p2p_manager: ConnectionsManager = self.manager2.connections

        # Initially, manager1 and manager2 are handshaking, from the setup
        assert p2p_manager._connections.connecting_outbound_peers() == set()
        assert p2p_manager._connections.handshaking_peers() == {self.conn.peer_addr1: self.conn.proto2}
        assert p2p_manager._connections.ready_peers() == {}

        # We change our peer id (on manager1)
        new_peer = PrivatePeer.auto_generated()
        self.conn.proto1.my_peer = new_peer
        self.conn.tr2._peer = new_peer

        # We advance the states and fail in the PEER-ID step (on manager2)
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'HELLO')
        self.conn.run_one_step()
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEER-ID')
        self.conn.run_one_step()
        assert self.conn.peek_tr2_value() == b'ERROR Peer id different from the requested one.\r\n'

    def test_invalid_expected_peer_id_bootstrap(self) -> None:
        p2p_manager: ConnectionsManager = self.manager1.connections

        # Initially, manager1 and manager2 are handshaking, from the setup
        assert p2p_manager._connections.connecting_outbound_peers() == set()
        assert p2p_manager._connections.handshaking_peers() == {self.conn.peer_addr2: self.conn.proto1}
        assert p2p_manager._connections.ready_peers() == {}

        # We create a new manager3, and use it as a bootstrap in manager1
        peer3 = PrivatePeer.auto_generated()
        manager3: HathorManager = self.create_peer(self.network, peer3)
        conn = FakeConnection(manager1=manager3, manager2=self.manager1, fake_bootstrap_id=peer3.id)

        # Now manager1 and manager3 are handshaking
        assert p2p_manager._connections.connecting_outbound_peers() == set()
        assert p2p_manager._connections.handshaking_peers() == {
            self.conn.peer_addr2: self.conn.proto1,
            conn.peer_addr1: conn.proto2,
        }
        assert p2p_manager._connections.ready_peers() == {}

        # We change our peer id (on manager3)
        new_peer = PrivatePeer.auto_generated()
        conn.proto1.my_peer = new_peer
        conn.tr2._peer = new_peer

        # We advance the states and fail in the PEER-ID step (on manager1)
        self._check_result_only_cmd(conn.peek_tr2_value(), b'HELLO')
        conn.run_one_step()
        self._check_result_only_cmd(conn.peek_tr2_value(), b'PEER-ID')
        conn.run_one_step()
        assert conn.peek_tr2_value() == b'ERROR Peer id different from the requested one.\r\n'

    def test_valid_unset_peer_id_bootstrap(self) -> None:
        p2p_manager: ConnectionsManager = self.manager1.connections

        # Initially, manager1 and manager2 are handshaking, from the setup
        assert p2p_manager._connections.connecting_outbound_peers() == set()
        assert p2p_manager._connections.handshaking_peers() == {self.conn.peer_addr2: self.conn.proto1}
        assert p2p_manager._connections.ready_peers() == {}

        # We create a new manager3, and use it as a bootstrap in manager1, but without the peer_id
        manager3: HathorManager = self.create_peer(self.network)
        conn = FakeConnection(manager1=manager3, manager2=self.manager1, fake_bootstrap_id=None)

        # Now manager1 and manager3 are handshaking
        assert p2p_manager._connections.connecting_outbound_peers() == set()
        assert p2p_manager._connections.handshaking_peers() == {
            self.conn.peer_addr2: self.conn.proto1,
            conn.peer_addr1: conn.proto2,
        }
        assert p2p_manager._connections.ready_peers() == {}

        # We change our peer id (on manager3)
        new_peer = PrivatePeer.auto_generated()
        conn.proto1.my_peer = new_peer
        conn.tr2._peer = new_peer

        # We advance the states and in this case succeed (on manager1), because
        # even though the peer_id was changed, it wasn't initially set.
        self._check_result_only_cmd(conn.peek_tr2_value(), b'HELLO')
        conn.run_one_step()
        self._check_result_only_cmd(conn.peek_tr2_value(), b'PEER-ID')
        conn.run_one_step()
        self._check_result_only_cmd(conn.peek_tr2_value(), b'READY')

    def test_exception_on_synchronous_cmd_handler(self) -> None:
        self.conn.run_one_step()
        self.conn.run_one_step()

        def error() -> None:
            raise Exception('some error')

        self.conn.proto1.state.cmd_map = {
            ProtocolMessages.READY: error
        }

        self.conn.run_one_step()
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "READY" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_exception_on_deferred_cmd_handler(self) -> None:
        self.conn.run_one_step()
        self.conn.run_one_step()

        self.conn.proto1.state.cmd_map = {
            ProtocolMessages.READY: lambda: defer.fail(Exception('some error')),
        }

        self.conn.run_one_step()
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "READY" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_exception_on_asynchronous_cmd_handler(self) -> None:
        self.conn.run_one_step()
        self.conn.run_one_step()

        async def error() -> None:
            raise Exception('some error')

        self.conn.proto1.state.cmd_map = {
            ProtocolMessages.READY: error
        }

        self.conn.run_one_step()
        self.clock.advance(1)
        assert self.conn.peek_tr1_value() == b'ERROR Error processing "READY" command\r\n'
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_two_connections(self) -> None:
        self.assertAndStepConn(self.conn, b'^HELLO')
        self.assertAndStepConn(self.conn, b'^PEER-ID')
        self.assertAndStepConn(self.conn, b'^READY')
        self.assertAndStepConn(self.conn, b'^GET-PEERS')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^PEERS')
        self.assertAndStepConn(self.conn, b'^BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^RELAY')
        self.assertIsConnected()

        # disable timeout because we will make several steps on a new conn and this might get left behind
        self.conn.disable_idle_timeout()

        manager3 = self.create_peer(self.network)
        conn = FakeConnection(self.manager1, manager3)
        self.assertAndStepConn(conn, b'^HELLO')
        self.assertAndStepConn(conn, b'^PEER-ID')
        self.assertAndStepConn(conn, b'^READY')
        self.assertAndStepConn(conn, b'^GET-PEERS')

        self.clock.advance(5)
        self.assertIsConnected()
        self.assertAndStepConn(self.conn, b'^GET-TIPS')
        self.assertAndStepConn(self.conn, b'^PING')

        self.assertIsConnected()

    def test_get_data(self) -> None:
        self.assertAndStepConn(self.conn, b'^HELLO')
        self.assertAndStepConn(self.conn, b'^PEER-ID')
        self.assertAndStepConn(self.conn, b'^READY')
        self.assertAndStepConn(self.conn, b'^GET-PEERS')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^PEERS')
        self.assertAndStepConn(self.conn, b'^BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^RELAY')
        self.assertIsConnected()
        missing_tx = '00000000228dfcd5dec1c9c6263f6430a5b4316bb9e3decb9441a6414bfd8697'
        payload = {
            'first_block_hash': missing_tx,
            'last_block_hash': missing_tx,
            'start_from': [self._settings.GENESIS_BLOCK_HASH.hex()]
        }
        self._send_cmd(self.conn.proto1, 'GET-TRANSACTIONS-BFS', json_dumps(payload))
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'NOT-FOUND')
        self.conn.run_one_step()

    def test_valid_hello_and_peer_id(self) -> None:
        self.assertAndStepConn(self.conn, b'^HELLO')
        self.assertAndStepConn(self.conn, b'^PEER-ID')
        self.assertAndStepConn(self.conn, b'^READY')
        self.assertAndStepConn(self.conn, b'^GET-PEERS')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^PEERS')
        self.assertAndStepConn(self.conn, b'^BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^RELAY')

        # this will tick the ping-pong mechanism and looping calls
        self.clock.advance(5)
        self.assertIsConnected()
        self.assertAndStepConn(self.conn, b'^GET-TIPS')
        self.assertAndStepConn(self.conn, b'^PING')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCKCHAIN')
        self.assertAndStepConn(self.conn, b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS-END')
        self.assertAndStepConn(self.conn, b'^PONG')
        self.assertIsConnected()

        self.clock.advance(5)
        self.assertAndStepConn(self.conn, b'^BEST-BLOCKCHAIN')
        self.assertAndStepConn(self.conn, b'^PING')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^PONG')
        self.assertAndStepConn(self.conn, b'^BEST-BLOCK')
        self.assertIsConnected()

    def test_send_ping(self) -> None:
        self.assertAndStepConn(self.conn, b'^HELLO')
        self.assertAndStepConn(self.conn, b'^PEER-ID')
        self.assertAndStepConn(self.conn, b'^READY')
        self.assertAndStepConn(self.conn, b'^GET-PEERS')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^PEERS')
        self.assertAndStepConn(self.conn, b'^BEST-BLOCK')
        self.assertAndStepConn(self.conn, b'^RELAY')

        # this will tick the ping-pong mechanism and looping calls
        self.clock.advance(5)
        self.assertAndStepConn(self.conn, b'^GET-TIPS')
        self.assertAndStepConn(self.conn, b'^PING')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCKCHAIN')
        self.assertAndStepConn(self.conn, b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS-END')
        self.assertRegex(self.conn.peek_tr1_value(), b'^PONG .*\r\n')
        self.assertRegex(self.conn.peek_tr2_value(), b'^PONG .*\r\n')
        while b'PONG\r\n' in self.conn.peek_tr1_value():
            self.conn.run_one_step()
        self.assertEqual(self.clock.seconds(), self.conn.proto1.last_message)
