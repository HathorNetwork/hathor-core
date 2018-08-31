from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.python import log

from hathor.p2p.peer_id import PeerId
from hathor.p2p.factory import HathorFactory

import sys


class HathorProtocolTestCase(unittest.TestCase):
    def setUp(self):
        log.startLogging(sys.stdout)
        peer_id = PeerId()
        self.network = 'testnet'
        factory = HathorFactory(peer_id=peer_id, network=self.network)

        self.proto = factory.buildProtocol(('127.0.0.1', 0))
        self.tr = proto_helpers.StringTransport()
        self.proto.makeConnection(self.tr)

    def _send_cmd(self, cmd, payload=None):
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        if isinstance(line, str):
            line = line.encode('utf-8')

        self.proto.dataReceived(line)

    def _check_result_only_cmd(self, result, expected_cmd):
        cmd, _, _ = result.partition(b' ')
        self.assertEqual(cmd, expected_cmd)

    def test_on_connect(self):
        self._check_result_only_cmd(self.tr.value(), b'HELLO')

    def test_invalid_command(self):
        self._send_cmd('INVALID-CMD')
        self.assertTrue(self.tr.disconnecting)

    def test_invalid_hello1(self):
        self.tr.clear()
        self._send_cmd('HELLO')
        self._check_result_only_cmd(self.tr.value(), b'ERROR')
        self.assertTrue(self.tr.disconnecting)

    def test_invalid_hello2(self):
        self.tr.clear()
        self._send_cmd('HELLO', 'invalid_payload')
        self._check_result_only_cmd(self.tr.value(), b'ERROR')
        self.assertTrue(self.tr.disconnecting)

    def test_invalid_hello3(self):
        self.tr.clear()
        self._send_cmd('HELLO', '{}')
        self._check_result_only_cmd(self.tr.value(), b'ERROR')
        self.assertTrue(self.tr.disconnecting)

    def test_valid_hello(self):
        peer_id = PeerId()
        factory = HathorFactory(peer_id=peer_id, network=self.network)
        proto2 = factory.buildProtocol(('127.0.0.1', 0))
        tr2 = proto_helpers.StringTransport()
        proto2.makeConnection(tr2)

        # Cross HELLO command.
        line1 = self.tr.value()
        line2 = tr2.value()

        self.tr.clear()
        tr2.clear()

        proto2.dataReceived(line1)
        self.proto.dataReceived(line2)

        self._check_result_only_cmd(self.tr.value(), b'PEER-ID')
        self._check_result_only_cmd(tr2.value(), b'PEER-ID')
        self.assertFalse(self.tr.disconnecting)
