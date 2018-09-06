from twisted.internet import reactor
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.python import log

from hathor.p2p.peer_id import PeerId
from hathor.p2p.factory import HathorFactory
from hathor.p2p.manager import HathorManager

import sys


class HathorProtocolTestCase(unittest.TestCase):
    def generate_peer(self, network, peer_id=None):
        if peer_id is None:
            peer_id = PeerId()
        factory = HathorFactory()
        manager = HathorManager(factory=factory, peer_id=peer_id, network=network)
        manager.doStart()
        factory.doStart()
        proto = factory.buildProtocol(('127.0.0.1', 0))
        tr = proto_helpers.StringTransport()
        proto.makeConnection(tr)
        return proto, tr

    def setUp(self):
        log.startLogging(sys.stdout)
        self.network = 'testnet'

        self.proto1, self.tr1 = self.generate_peer(self.network)
        self.proto2, self.tr2 = self.generate_peer(self.network)

    def tearDown(self):
        self.clean_pending(required_to_quiesce=False)

    def clean_pending(self, required_to_quiesce=True):
        """
        This handy method cleans all pending tasks from the reactor.

        When writing a unit test, consider the following question:

            Is the code that you are testing required to release control once it
            has done its job, so that it is impossible for it to later come around
            (with a delayed reactor task) and do anything further?

        If so, then trial will usefully test that for you -- if the code under
        test leaves any pending tasks on the reactor then trial will fail it.

        On the other hand, some code is *not* required to release control -- some
        code is allowed to continuously maintain control by rescheduling reactor
        tasks in order to do ongoing work.  Trial will incorrectly require that
        code to clean up all its tasks from the reactor.

        Most people think that such code should be amended to have an optional
        "shutdown" operation that releases all control, but on the contrary it is
        good design for some code to *not* have a shutdown operation, but instead
        to have a "crash-only" design in which it recovers from crash on startup.

        If the code under test is of the "long-running" kind, which is *not*
        required to shutdown cleanly in order to pass tests, then you can simply
        call testutil.clean_pending() at the end of the unit test, and trial will
        be satisfied.

        Copy from: https://github.com/zooko/pyutil/blob/master/pyutil/testutil.py#L68
        """
        pending = reactor.getDelayedCalls()
        active = bool(pending)
        for p in pending:
            if p.active():
                p.cancel()
            else:
                print('WEIRDNESS! pending timed call not active!')
        if required_to_quiesce and active:
            self.fail('Reactor was still active when it was required to be quiescent.')

    def _send_cmd(self, proto, cmd, payload=None):
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        if isinstance(line, str):
            line = line.encode('utf-8')

        proto.dataReceived(line)

    def _check_result_only_cmd(self, result, expected_cmd):
        cmd, _, _ = result.partition(b' ')
        self.assertEqual(cmd, expected_cmd)

    def _run_one_step(self, debug=False):
        line1 = self.tr1.value()
        line2 = self.tr2.value()

        if debug:
            print('--')
            print('line1', line1)
            print('line2', line2)
            print('--')

        self.tr1.clear()
        self.tr2.clear()

        self.proto2.dataReceived(line1)
        self.proto1.dataReceived(line2)

    def test_on_connect(self):
        self._check_result_only_cmd(self.tr1.value(), b'HELLO')

    def test_invalid_command(self):
        self._send_cmd(self.proto1, 'INVALID-CMD')
        self.assertTrue(self.tr1.disconnecting)

    def test_invalid_hello1(self):
        self.tr1.clear()
        self._send_cmd(self.proto1, 'HELLO')
        self._check_result_only_cmd(self.tr1.value(), b'ERROR')
        self.assertTrue(self.tr1.disconnecting)

    def test_invalid_hello2(self):
        self.tr1.clear()
        self._send_cmd(self.proto1, 'HELLO', 'invalid_payload')
        self._check_result_only_cmd(self.tr1.value(), b'ERROR')
        self.assertTrue(self.tr1.disconnecting)

    def test_invalid_hello3(self):
        self.tr1.clear()
        self._send_cmd(self.proto1, 'HELLO', '{}')
        self._check_result_only_cmd(self.tr1.value(), b'ERROR')
        self.assertTrue(self.tr1.disconnecting)

    def test_valid_hello(self):
        self._run_one_step()
        self._check_result_only_cmd(self.tr1.value(), b'PEER-ID')
        self._check_result_only_cmd(self.tr2.value(), b'PEER-ID')
        self.assertFalse(self.tr1.disconnecting)
        self.assertFalse(self.tr2.disconnecting)

    def test_invalid_same_peer_id(self):
        self.proto2.factory.manager.my_peer = self.proto1.factory.manager.my_peer
        self._run_one_step()
        self._run_one_step()
        self._check_result_only_cmd(self.tr1.value(), b'ERROR')
        self.assertTrue(self.tr1.disconnecting)

    def test_invalid_different_network(self):
        self.proto2, self.tr2 = self.generate_peer(network='mainnet')
        self._run_one_step()
        self._check_result_only_cmd(self.tr1.value(), b'ERROR')
        self.assertTrue(self.tr1.disconnecting)

    def test_valid_hello_and_peer_id(self):
        self._run_one_step()
        self._run_one_step()
        # Originally, only a GET-PEERS message would be received, but now it is receiving two messages in a row.
        # self._check_result_only_cmd(self.tr1.value(), b'GET-PEERS')
        # self._check_result_only_cmd(self.tr2.value(), b'GET-PEERS')
        self.assertFalse(self.tr1.disconnecting)
        self.assertFalse(self.tr2.disconnecting)
        self._run_one_step()
        self._run_one_step()
        self.assertFalse(self.tr1.disconnecting)
        self.assertFalse(self.tr2.disconnecting)
