from json import JSONDecodeError
from typing import Optional

from twisted.internet.defer import inlineCallbacks
from twisted.python.failure import Failure

from hathor.conf import get_settings
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from hathor.simulator import FakeConnection
from hathor.util import json_dumps
from tests import unittest

settings = get_settings()


class BaseHathorProtocolTestCase(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.network = 'testnet'
        self.peer_id1 = PeerId()
        self.peer_id2 = PeerId()
        self.manager1 = self.create_peer(self.network, peer_id=self.peer_id1)
        self.manager2 = self.create_peer(self.network, peer_id=self.peer_id2)
        self.conn = FakeConnection(self.manager1, self.manager2)

    def assertAndStepConn(self, conn: FakeConnection, regex1: bytes, regex2: Optional[bytes] = None) -> None:
        """If only one regex is given it is tested on both cons, if two are given they'll be used respectively."""
        if regex2 is None:
            regex2 = regex1
        self.assertRegex(conn.peek_tr1_value(), regex1)
        self.assertRegex(conn.peek_tr2_value(), regex2)
        conn.run_one_step()

    def assertIsConnected(self, conn=None):
        if conn is None:
            conn = self.conn
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

    def assertIsNotConnected(self, conn=None):
        if conn is None:
            conn = self.conn
        self.assertTrue(conn.tr1.disconnecting)
        self.assertTrue(conn.tr2.disconnecting)

    def _send_cmd(self, proto, cmd, payload=None):
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        if isinstance(line, str):
            line = line.encode('utf-8')

        return proto.dataReceived(line)

    def _check_result_only_cmd(self, result, expected_cmd):
        cmd_list = []
        for line in result.split(b'\r\n'):
            cmd, _, _ = line.partition(b' ')
            cmd_list.append(cmd)
        self.assertIn(expected_cmd, cmd_list)

    def _check_cmd_and_value(self, result, expected):
        result_list = []
        for line in result.split(b'\r\n'):
            cmd, _, data = line.partition(b' ')
            result_list.append((cmd, data))
        self.assertIn(expected, result_list)

    def test_on_connect(self):
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'HELLO')

    def test_invalid_command(self):
        self._send_cmd(self.conn.proto1, 'INVALID-CMD')
        self.conn.proto1.state.handle_error('')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_rate_limit(self):
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
        self.conn.proto1.connections = None
        self.conn.proto1.on_disconnect(Failure(Exception()))

    def test_invalid_size(self):
        self.conn.tr1.clear()
        # Creating big payload
        big_payload = '['
        for x in range(65536):
            big_payload = '{}{}'.format(big_payload, x)
        big_payload = '{}]'.format(big_payload)
        self._send_cmd(self.conn.proto1, 'HELLO', big_payload)
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_payload(self):
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        with self.assertRaises(JSONDecodeError):
            self._send_cmd(self.conn.proto1, 'PEERS', 'abc')

    def test_invalid_hello1(self):
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello2(self):
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO', 'invalid_payload')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello3(self):
        self.conn.tr1.clear()
        self._send_cmd(self.conn.proto1, 'HELLO', '{}')
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello4(self):
        self.conn.tr1.clear()
        self._send_cmd(
            self.conn.proto1,
            'HELLO',
            '{"app": 0, "remote_address": 1, "network": 2, "genesis_hash": "123", "settings_hash": "456"}'
        )
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_invalid_hello5(self):
        # hello with clocks too far apart
        self.conn.tr1.clear()
        data = self.conn.proto2.state._get_hello_data()
        data['timestamp'] = data['timestamp'] + settings.MAX_FUTURE_TIMESTAMP_ALLOWED/2 + 1
        self._send_cmd(
            self.conn.proto1,
            'HELLO',
            json_dumps(data),
        )
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_valid_hello(self):
        self.conn.run_one_step()  # HELLO
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEER-ID')
        self.assertFalse(self.conn.tr1.disconnecting)
        self.assertFalse(self.conn.tr2.disconnecting)

    def test_invalid_same_peer_id(self):
        manager3 = self.create_peer(self.network, peer_id=self.peer_id1)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        self._check_result_only_cmd(conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)

    def test_invalid_same_peer_id2(self):
        """
        We connect nodes 1-2 and 1-3. Nodes 2 and 3 have the same peer_id. The connections
        are established simultaneously, so we do not detect a peer id duplication in PEER_ID
        state, only on READY state.
        """
        # Disable idle timeout before creating any new peer because self.create_peer(...)
        # runs the main loop.
        self.conn.disable_idle_timeout()
        # Create new peer and disable idle timeout.
        manager3 = self.create_peer(self.network, peer_id=self.peer_id2)
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

        if self.conn.tr1.disconnecting or self.conn.tr2.disconnecting:
            conn_dead = self.conn
            conn_alive = conn
        elif conn.tr1.disconnecting or conn.tr2.disconnecting:
            conn_dead = conn
            conn_alive = self.conn
        else:
            raise Exception('It should never happen.')
        self._check_result_only_cmd(conn_dead.peek_tr1_value() + conn_dead.peek_tr2_value(), b'ERROR')
        # at this point, the connection must be closing as the error was detected on READY state
        self.assertIn(True, [conn_dead.tr1.disconnecting, conn_dead.tr2.disconnecting])
        # check connected_peers
        connected_peers = list(self.manager1.connections.connected_peers.values())
        self.assertEquals(1, len(connected_peers))
        self.assertIn(connected_peers[0], [conn_alive.proto1, conn_alive.proto2])
        # connection is still up
        self.assertIsConnected(conn_alive)

    def test_invalid_different_network(self):
        manager3 = self.create_peer(network='mainnet')
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        self._check_result_only_cmd(conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)
        conn.run_one_step()  # ERROR

    def test_send_invalid_unicode(self):
        # \xff is an invalid unicode.
        self.conn.proto1.dataReceived(b'\xff\r\n')
        self.assertTrue(self.conn.tr1.disconnecting)

    def test_on_disconnect(self):
        self.assertIn(self.conn.proto1, self.manager1.connections.handshaking_peers)
        self.conn.disconnect(Failure(Exception('testing')))
        self.assertNotIn(self.conn.proto1, self.manager1.connections.handshaking_peers)

    def test_on_disconnect_after_hello(self):
        self.conn.run_one_step()  # HELLO
        self.assertIn(self.conn.proto1, self.manager1.connections.handshaking_peers)
        self.conn.disconnect(Failure(Exception('testing')))
        self.assertNotIn(self.conn.proto1, self.manager1.connections.handshaking_peers)

    def test_on_disconnect_after_peer_id(self):
        self.conn.run_one_step()  # HELLO
        self.assertIn(self.conn.proto1, self.manager1.connections.handshaking_peers)
        # No peer id in the peer_storage (known_peers)
        self.assertNotIn(self.peer_id2.id, self.manager1.connections.peer_storage)
        # The peer READY now depends on a message exchange from both peers, so we need one more step
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.assertIn(self.conn.proto1, self.manager1.connections.connected_peers.values())
        # Peer id 2 in the peer_storage (known_peers) after connection
        self.assertIn(self.peer_id2.id, self.manager1.connections.peer_storage)
        self.assertNotIn(self.conn.proto1, self.manager1.connections.handshaking_peers)
        self.conn.disconnect(Failure(Exception('testing')))
        # Peer id 2 in the peer_storage (known_peers) after disconnection but before looping call
        self.assertIn(self.peer_id2.id, self.manager1.connections.peer_storage)
        self.assertNotIn(self.conn.proto1, self.manager1.connections.connected_peers.values())

        self.clock.advance(10)
        # Peer id 2 removed from peer_storage (known_peers) after disconnection and after looping call
        self.assertNotIn(self.peer_id2.id, self.manager1.connections.peer_storage)

    def test_idle_connection(self):
        self.clock.advance(settings.PEER_IDLE_TIMEOUT - 10)
        self.assertIsConnected(self.conn)
        self.clock.advance(15)
        self.assertIsNotConnected(self.conn)


class SyncV1HathorProtocolTestCase(unittest.SyncV1Params, BaseHathorProtocolTestCase):
    __test__ = True

    def test_two_connections(self):
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.conn.run_one_step()  # GET-PEERS
        self.conn.run_one_step()  # GET-TIPS

        manager3 = self.create_peer(self.network)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID
        conn.run_one_step()  # READY
        conn.run_one_step()  # GET-PEERS

        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEERS')
        self.conn.run_one_step()

    @inlineCallbacks
    def test_get_data(self):
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.conn.run_one_step()  # GET-PEERS
        self.conn.run_one_step()  # GET-TIPS
        self.conn.run_one_step()  # PEERS
        self.conn.run_one_step()  # TIPS
        self.assertIsConnected()
        missing_tx = '00000000228dfcd5dec1c9c6263f6430a5b4316bb9e3decb9441a6414bfd8697'
        yield self._send_cmd(self.conn.proto1, 'GET-DATA', missing_tx)
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'NOT-FOUND')
        self.conn.run_one_step()

    def test_valid_hello_and_peer_id(self):
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'HELLO')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'HELLO')
        self.conn.run_one_step()  # HELLO
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEER-ID')
        self.conn.run_one_step()  # PEER-ID
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'READY')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'READY')
        self.conn.run_one_step()  # READY
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'GET-PEERS')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'GET-PEERS')
        self.conn.run_one_step()  # GET-PEERS
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'GET-TIPS')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'GET-TIPS')
        self.conn.run_one_step()  # GET-TIPS
        self.assertIsConnected()
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'PEERS')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'PEERS')
        self.conn.run_one_step()  # PEERS
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'TIPS')
        self._check_result_only_cmd(self.conn.peek_tr2_value(), b'TIPS')
        self.conn.run_one_step()  # TIPS
        self.assertIsConnected()

    def test_send_ping(self):
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.conn.run_one_step()  # GET-PEERS
        self.conn.run_one_step()  # GET-TIPS
        self.conn.run_one_step()  # PEERS
        self.conn.run_one_step()  # TIPS
        self.assertIsConnected()
        self.clock.advance(5)
        self.assertEqual(b'PING\r\n', self.conn.peek_tr1_value())
        self.assertEqual(b'PING\r\n', self.conn.peek_tr2_value())
        self.conn.run_one_step()  # PING
        self.conn.run_one_step()  # GET-TIPS
        self.conn.run_one_step()  # GET-BEST-BLOCKCHAIN
        self.assertEqual(b'PONG\r\n', self.conn.peek_tr1_value())
        self.assertEqual(b'PONG\r\n', self.conn.peek_tr2_value())
        while b'PONG\r\n' in self.conn.peek_tr1_value():
            self.conn.run_one_step()
        self.assertEqual(self.clock.seconds(), self.conn.proto1.last_message)

    @inlineCallbacks
    def test_invalid_peer_id(self):
        self.conn.run_one_step()  # HELLO
        self.conn.run_one_step()  # PEER-ID
        self.conn.run_one_step()  # READY
        self.conn.run_one_step()  # GET-PEERS
        self.conn.run_one_step()  # GET-TIPS
        self.conn.run_one_step()  # PEERS
        self.conn.run_one_step()  # TIPS
        invalid_payload = {'id': '123', 'entrypoints': ['tcp://localhost:1234']}
        yield self._send_cmd(self.conn.proto1, 'PEER-ID', json_dumps(invalid_payload))
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'ERROR')
        self.assertTrue(self.conn.tr1.disconnecting)


class SyncV2HathorProtocolTestCase(unittest.SyncV2Params, BaseHathorProtocolTestCase):
    __test__ = True

    def test_two_connections(self):
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

        manager3 = self.create_peer(self.network, enable_sync_v2=True)
        conn = FakeConnection(self.manager1, manager3)
        self.assertAndStepConn(conn, b'^HELLO')
        self.assertAndStepConn(conn, b'^PEER-ID')
        self.assertAndStepConn(conn, b'^READY')
        self.assertAndStepConn(conn, b'^GET-PEERS')

        self.clock.advance(5)
        self.assertIsConnected()
        self.assertAndStepConn(self.conn, b'^GET-TIPS')
        self.assertAndStepConn(self.conn, b'^PING')

        for _ in range(19):
            self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCKCHAIN')

        # peer1 should now send a PEERS with the new peer that just connected
        self.assertAndStepConn(self.conn, b'^PEERS',    b'^GET-BEST-BLOCKCHAIN')
        self.assertAndStepConn(self.conn, b'^GET-BEST-BLOCKCHAIN',    b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS',     b'^TIPS')
        self.assertAndStepConn(self.conn, b'^TIPS',     b'^TIPS-END')
        self.assertAndStepConn(self.conn, b'^TIPS-END', b'^PONG')
        self.assertAndStepConn(self.conn, b'^PONG',     b'^BEST-BLOCKCHAIN')
        self.assertIsConnected()

    @inlineCallbacks
    def test_get_data(self):
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
        payload = {'until_first_block': missing_tx, 'start_from': [settings.GENESIS_BLOCK_HASH.hex()]}
        yield self._send_cmd(self.conn.proto1, 'GET-TRANSACTIONS-BFS', json_dumps(payload))
        self._check_result_only_cmd(self.conn.peek_tr1_value(), b'NOT-FOUND')
        self.conn.run_one_step()

    def test_valid_hello_and_peer_id(self):
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

    def test_send_ping(self):
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
        self.assertEqual(b'PONG\r\n', self.conn.peek_tr1_value())
        self.assertEqual(b'PONG\r\n', self.conn.peek_tr2_value())
        while b'PONG\r\n' in self.conn.peek_tr1_value():
            self.conn.run_one_step()
        self.assertEqual(self.clock.seconds(), self.conn.proto1.last_message)


# sync-bridge should behave like sync-v2
class SyncBridgeHathorProtocolTestCase(unittest.SyncBridgeParams, SyncV2HathorProtocolTestCase):
    pass
