import json

import twisted.names.client
from twisted.internet.defer import inlineCallbacks

from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorProtocol
from tests import unittest
from tests.utils import FakeConnection


class HathorProtocolTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.network = 'testnet'

        self.peer_id1 = PeerId()
        self.peer_id2 = PeerId()
        self.manager1 = self.create_peer(self.network, peer_id=self.peer_id1)
        self.manager2 = self.create_peer(self.network, peer_id=self.peer_id2)

        self.conn1 = FakeConnection(self.manager1, self.manager2)

    def assertIsConnected(self, conn=None):
        if conn is None:
            conn = self.conn1
        self.assertFalse(conn.tr1.disconnecting)
        self.assertFalse(conn.tr2.disconnecting)

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
        self._check_result_only_cmd(self.conn1.tr1.value(), b'HELLO')

    def test_invalid_command(self):
        self._send_cmd(self.conn1.proto1, 'INVALID-CMD')
        self.conn1.proto1.state.handle_error('')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_rate_limit(self):
        hits = 1
        window = 60
        self.conn1.proto1.ratelimit.set_limit(HathorProtocol.RateLimitKeys.GLOBAL, hits, window)
        # First will be ignored
        self._send_cmd(self.conn1.proto1, 'HELLO')
        # Second will reach limit
        self._send_cmd(self.conn1.proto1, 'HELLO')

        self._check_cmd_and_value(
            self.conn1.tr1.value(),
            (b'THROTTLE', 'global At most {} hits every {} seconds'.format(hits, window).encode('utf-8')))

        self.conn1.proto1.state.handle_throttle(b'')

        # Test empty disconnect
        self.conn1.proto1.state = None
        self.conn1.proto1.connections = None
        self.conn1.proto1.on_disconnect('')

    def test_invalid_size(self):
        self.conn1.tr1.clear()
        # Creating big payload
        big_payload = '['
        for x in range(65536):
            big_payload = '{}{}'.format(big_payload, x)
        big_payload = '{}]'.format(big_payload)
        self._send_cmd(self.conn1.proto1, 'HELLO', big_payload)
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_invalid_payload(self):
        self.conn1.run_one_step()
        self.failureResultOf(self._send_cmd(self.conn1.proto1, 'PEER-ID', 'abc'), json.decoder.JSONDecodeError)

    def test_invalid_hello1(self):
        self.conn1.tr1.clear()
        self._send_cmd(self.conn1.proto1, 'HELLO')
        self._check_result_only_cmd(self.conn1.tr1.value(), b'ERROR')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_invalid_hello2(self):
        self.conn1.tr1.clear()
        self._send_cmd(self.conn1.proto1, 'HELLO', 'invalid_payload')
        self._check_result_only_cmd(self.conn1.tr1.value(), b'ERROR')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_invalid_hello3(self):
        self.conn1.tr1.clear()
        self._send_cmd(self.conn1.proto1, 'HELLO', '{}')
        self._check_result_only_cmd(self.conn1.tr1.value(), b'ERROR')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_invalid_hello4(self):
        self.conn1.tr1.clear()
        self._send_cmd(
            self.conn1.proto1,
            'HELLO',
            '{"app": 0, "remote_address": 1, "network": 2, "genesis_hash": "123", "settings_hash": "456"}'
        )
        self._check_result_only_cmd(self.conn1.tr1.value(), b'ERROR')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_valid_hello(self):
        self.conn1.run_one_step()
        self._check_result_only_cmd(self.conn1.tr1.value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn1.tr2.value(), b'PEER-ID')
        self.assertFalse(self.conn1.tr1.disconnecting)
        self.assertFalse(self.conn1.tr2.disconnecting)

    @inlineCallbacks
    def test_invalid_peer_id(self):
        self.conn1.run_one_step()
        invalid_payload = {'id': '123', 'entrypoints': ['tcp://localhost:1234']}
        yield self._send_cmd(self.conn1.proto1, 'PEER-ID', json.dumps(invalid_payload))
        self._check_result_only_cmd(self.conn1.tr1.value(), b'ERROR')
        self.assertTrue(self.conn1.tr1.disconnecting)
        # When a DNS request is made to twisted client, it starts a callLater to check the resolv file every minute
        # https://github.com/twisted/twisted/blob/59f8266c286e2b073ddb05c70317ac20693f2b0c/src/twisted/names/client.py#L147  # noqa
        # So we need to stop this call manually, otherwise the reactor would be unclean with a pending call
        # TODO We should use a fake DNS resolver for tests otherwise we would need internet connection to run it
        resolver = twisted.names.client.getResolver().resolvers[2]
        resolver._parseCall.cancel()

    def test_invalid_same_peer_id(self):
        manager3 = self.create_peer(self.network, peer_id=self.peer_id1)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()
        conn.run_one_step()
        self._check_result_only_cmd(conn.tr1.value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)

    def test_invalid_same_peer_id2(self):
        # we connect nodes 1-2 and 1-3. Nodes 2 and 3 have the same peer_id. The connections
        # are established simultaneously, so we do not detect a peer id duplication in PEER_ID
        # state, only on READY state
        manager3 = self.create_peer(self.network, peer_id=self.peer_id2)
        conn = FakeConnection(self.manager1, manager3)
        self.conn1.run_one_step()
        conn.run_one_step()
        self.conn1.run_one_step()
        conn.run_one_step()
        self.conn1.run_one_step()
        conn.run_one_step()
        # at this point, the connection must be closing as the error was detected on READY state
        self._check_result_only_cmd(conn.tr1.value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)
        # we go through with disconnecting nodes 2-3 and make sure the original connection (nodes 1-2)
        # is still on the connected_peers dict
        conn.disconnect('test')
        self.assertIn(self.conn1.proto1, self.manager1.connections.connected_peers.values())
        # original connection (nodes 1-2) is still up
        self.assertIsConnected()

    def test_invalid_different_network(self):
        manager3 = self.create_peer(network='mainnet')
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()
        self._check_result_only_cmd(conn.tr1.value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)
        conn.run_one_step()

    def test_valid_hello_and_peer_id(self):
        self.conn1.run_one_step()
        self.conn1.run_one_step()
        # Originally, only a GET-PEERS message would be received, but now it is receiving two messages in a row.
        # self._check_result_only_cmd(self.tr1.value(), b'GET-PEERS')
        # self._check_result_only_cmd(self.tr2.value(), b'GET-PEERS')
        self.assertIsConnected()
        self.conn1.run_one_step()
        self.conn1.run_one_step()
        self.assertIsConnected()

    def test_send_ping(self):
        self.conn1.run_one_step()
        self.conn1.run_one_step()
        self.conn1.run_one_step()
        # Originally, only a GET-PEERS message would be received, but now it is receiving two messages in a row.
        # self._check_result_only_cmd(self.tr1.value(), b'GET-PEERS')
        # self._check_result_only_cmd(self.tr2.value(), b'GET-PEERS')
        self.assertIsConnected()
        self.clock.advance(5)
        self.assertTrue(b'PING\r\n' in self.conn1.tr1.value())
        self.assertTrue(b'PING\r\n' in self.conn1.tr2.value())
        self.conn1.run_one_step()
        self.assertTrue(b'PONG\r\n' in self.conn1.tr1.value())
        self.assertTrue(b'PONG\r\n' in self.conn1.tr2.value())
        while b'PONG\r\n' in self.conn1.tr1.value():
            self.conn1.run_one_step()
        self.assertEqual(self.clock.seconds(), self.conn1.proto1.last_message)

    def test_send_invalid_unicode(self):
        # \xff is an invalid unicode.
        self.conn1.proto1.dataReceived(b'\xff\r\n')
        self.assertTrue(self.conn1.tr1.disconnecting)

    def test_on_disconnect(self):
        self.assertIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)
        self.conn1.disconnect('Testing')
        self.assertNotIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)

    def test_on_disconnect_after_hello(self):
        self.conn1.run_one_step()
        self.assertIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)
        self.conn1.disconnect('Testing')
        self.assertNotIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)

    def test_on_disconnect_after_peer_id(self):
        self.conn1.run_one_step()
        self.assertIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)
        # The peer READY now depends on a message exchange from both peers, so we need one more step
        self.conn1.run_one_step()
        self.conn1.run_one_step()
        self.assertIn(self.conn1.proto1, self.manager1.connections.connected_peers.values())
        self.assertNotIn(self.conn1.proto1, self.manager1.connections.handshaking_peers)
        self.conn1.disconnect('Testing')
        self.assertNotIn(self.conn1.proto1, self.manager1.connections.connected_peers.values())

    def test_two_connections(self):
        self.conn1.run_one_step()  # HELLO
        self.conn1.run_one_step()  # PEER-ID
        self.conn1.run_one_step()  # GET-PEERS
        self.conn1.run_one_step()  # GET-TIPS

        manager3 = self.create_peer(self.network)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()  # HELLO
        conn.run_one_step()  # PEER-ID

        self._check_result_only_cmd(self.conn1.tr1.value(), b'PEERS')
        self.conn1.run_one_step()
