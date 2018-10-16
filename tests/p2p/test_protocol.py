from twisted.python import log
from twisted.internet.task import Clock

from hathor.p2p.peer_id import PeerId
from tests.utils import FakeConnection
from tests import unittest

import sys


class HathorProtocolTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        log.startLogging(sys.stdout)

        self.clock = Clock()
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

        proto.dataReceived(line)

    def _check_result_only_cmd(self, result, expected_cmd):
        cmd_list = []
        for line in expected_cmd.split(b'\r\n'):
            cmd, _, _ = line.partition(b' ')
            cmd_list.append(cmd)
        self.assertIn(expected_cmd, cmd_list)

    def test_on_connect(self):
        self._check_result_only_cmd(self.conn1.tr1.value(), b'HELLO')

    def test_invalid_command(self):
        self._send_cmd(self.conn1.proto1, 'INVALID-CMD')
        self.assertTrue(self.conn1.tr1.disconnecting)

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

    def test_valid_hello(self):
        self.conn1.run_one_step()
        self._check_result_only_cmd(self.conn1.tr1.value(), b'PEER-ID')
        self._check_result_only_cmd(self.conn1.tr2.value(), b'PEER-ID')
        self.assertFalse(self.conn1.tr1.disconnecting)
        self.assertFalse(self.conn1.tr2.disconnecting)

    def test_invalid_same_peer_id(self):
        manager3 = self.create_peer(self.network, peer_id=self.peer_id1)
        conn = FakeConnection(self.manager1, manager3)
        conn.run_one_step()
        conn.run_one_step()
        self._check_result_only_cmd(conn.tr1.value(), b'ERROR')
        self.assertTrue(conn.tr1.disconnecting)

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
