
from collections import deque
from typing import TYPE_CHECKING, Deque

from OpenSSL.crypto import X509
from twisted.test import proto_helpers

from hathor.conf import HathorSettings
from hathor.p2p.utils import generate_certificate

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.p2p.peer_id import PeerId

settings = HathorSettings()


class HathorStringTransport(proto_helpers.StringTransport):
    def __init__(self, peer: 'PeerId'):
        self.peer = peer
        super().__init__()

    def getPeerCertificate(self) -> X509:
        certificate = generate_certificate(self.peer.private_key, settings.CA_FILEPATH, settings.CA_KEY_FILEPATH)
        openssl_certificate = X509.from_cryptography(certificate)
        return openssl_certificate


class FakeConnection:
    def __init__(self, manager1: 'HathorManager', manager2: 'HathorManager', *, latency: float = 0):
        """
        :param: latency: Latency between nodes in seconds
        """
        self.manager1 = manager1
        self.manager2 = manager2

        self.latency = latency
        self.is_connected = True

        self._proto1 = manager1.server_factory.buildProtocol(('127.0.0.1', 0))
        self._proto2 = manager2.client_factory.buildProtocol(('127.0.0.1', 0))

        self.tr1 = HathorStringTransport(self._proto2.my_peer)
        self.tr2 = HathorStringTransport(self._proto1.my_peer)

        self._do_buffering = True
        self._buf1: Deque[str] = deque()
        self._buf2: Deque[str] = deque()

        self._proto1.makeConnection(self.tr1)
        self._proto2.makeConnection(self.tr2)

    @property
    def proto1(self):
        return self._proto1

    @property
    def proto2(self):
        return self._proto2

    def disable_idle_timeout(self):
        """Disable timeout in both peers."""
        self._proto1.disable_idle_timeout()
        self._proto2.disable_idle_timeout()

    def run_one_step(self, debug=False, force=False):
        assert self.is_connected, 'not connected'

        if debug:
            print('[do step]')

        if self._do_buffering:
            if not self._buf1:
                self._buf1.extend(self.tr1.value().splitlines(keepends=True))
                self.tr1.clear()
            if not self._buf2:
                self._buf2.extend(self.tr2.value().splitlines(keepends=True))
                self.tr2.clear()
            if self._buf1:
                line1 = self._buf1.popleft()
            else:
                line1 = b''
            if self._buf2:
                line2 = self._buf2.popleft()
            else:
                line2 = b''
        else:
            line1 = self.tr1.value()
            self.tr1.clear()
            line2 = self.tr2.value()
            self.tr2.clear()

        if line1:
            if self.latency > 0:
                self.manager1.reactor.callLater(self.latency, self._deliver_message, self._proto2, line1, debug)
                if debug:
                    print('[1->2] delayed by', self.latency)
            else:
                self._proto2.dataReceived(line1)
                if debug:
                    print('[1->2]', line1)

        if line2:
            if self.latency > 0:
                self.manager2.reactor.callLater(self.latency, self._deliver_message, self._proto1, line2, debug)
                if debug:
                    print('[1->2] delayed by', self.latency)
            else:
                self._proto1.dataReceived(line2)
                if debug:
                    print('[2->1]', line2)

        return True

    def run_until_complete(self, debug=False, force=False):
        while not self.is_empty():
            self.run_one_step(debug=debug, force=force)

    def _deliver_message(self, proto, data, debug=False):
        proto.dataReceived(data)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self._proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self._proto2.connectionLost(reason)
        self.is_connected = False

    def is_empty(self):
        if self._do_buffering and (self._buf1 or self._buf2):
            return False
        return not self.tr1.value() and not self.tr2.value()

    def peek_tr1_value(self):
        if self._do_buffering and self._buf1:
            return self._buf1[0]
        value = self.tr1.value()
        if not value:
            return b''
        return value.splitlines(keepends=True)[0]

    def peek_tr2_value(self):
        if self._do_buffering and self._buf2:
            return self._buf2[0]
        value = self.tr2.value()
        if not value:
            return b''
        return value.splitlines(keepends=True)[0]
