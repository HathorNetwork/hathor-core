# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import deque
from typing import TYPE_CHECKING, Optional

from OpenSSL.crypto import X509
from structlog import get_logger
from twisted.internet.address import HostnameAddress
from twisted.internet.testing import StringTransport

from hathor.conf import HathorSettings

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.p2p.peer_id import PeerId

settings = HathorSettings()
logger = get_logger()


class HathorStringTransport(StringTransport):
    def __init__(self, peer: 'PeerId'):
        super().__init__()
        self.peer = peer

    def getPeerCertificate(self) -> X509:
        certificate = self.peer.get_certificate()
        return X509.from_cryptography(certificate)


class FakeConnection:
    def __init__(self, manager1: 'HathorManager', manager2: 'HathorManager', *, latency: float = 0,
                 autoreconnect: bool = False):
        """
        :param: latency: Latency between nodes in seconds
        """
        self.log = logger.new()

        self.manager1 = manager1
        self.manager2 = manager2

        self.latency = latency
        self.autoreconnect = autoreconnect
        self.is_connected = False

        self._do_buffering = True
        self._buf1: deque[str] = deque()
        self._buf2: deque[str] = deque()

        self.reconnect()

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

    def is_both_synced(self) -> bool:
        """Short-hand check that can be used to make "step loops" without having to guess the number of iterations."""
        from hathor.p2p.states.ready import ReadyState
        conn1_aborting = self._proto1.aborting
        conn2_aborting = self._proto2.aborting
        if conn1_aborting or conn2_aborting:
            self.log.debug('conn aborting', conn1_aborting=conn1_aborting, conn2_aborting=conn2_aborting)
            return False
        state1 = self._proto1.state
        state2 = self._proto2.state
        state1_is_ready = isinstance(state1, ReadyState)
        state2_is_ready = isinstance(state2, ReadyState)
        if not state1_is_ready or not state2_is_ready:
            self.log.debug('peer not ready', peer1_ready=state1_is_ready, peer2_ready=state2_is_ready)
            return False
        assert isinstance(state1, ReadyState)  # mypy can't infer this from the above
        assert isinstance(state2, ReadyState)  # mypy can't infer this from the above
        state1_is_errored = state1.sync_manager.is_errored()
        state2_is_errored = state2.sync_manager.is_errored()
        if state1_is_errored or state2_is_errored:
            self.log.debug('peer errored', peer1_errored=state1_is_errored, peer2_errored=state2_is_errored)
            return False
        state1_is_synced = state1.sync_manager.is_synced()
        state2_is_synced = state2.sync_manager.is_synced()
        if not state1_is_synced or not state2_is_synced:
            self.log.debug('peer not synced', peer1_synced=state1_is_synced, peer2_synced=state2_is_synced)
            return False
        return True

    def can_step(self) -> bool:
        """Short-hand check that can be used to make "step loops" without having to guess the number of iterations."""
        from hathor.p2p.states.ready import ReadyState
        conn1_aborting = self._proto1.aborting
        conn2_aborting = self._proto2.aborting
        if conn1_aborting or conn2_aborting:
            self.log.debug('conn aborting', conn1_aborting=conn1_aborting, conn2_aborting=conn2_aborting)
            return False
        state1 = self._proto1.state
        state2 = self._proto2.state
        state1_is_ready = isinstance(state1, ReadyState)
        state2_is_ready = isinstance(state2, ReadyState)
        if not state1_is_ready or not state2_is_ready:
            self.log.debug('peer not ready', peer1_ready=state1_is_ready, peer2_ready=state2_is_ready)
            return True
        assert isinstance(state1, ReadyState)  # mypy can't infer this from the above
        assert isinstance(state2, ReadyState)  # mypy can't infer this from the above
        state1_is_errored = state1.sync_manager.is_errored()
        state2_is_errored = state2.sync_manager.is_errored()
        if state1_is_errored or state2_is_errored:
            self.log.debug('peer errored', peer1_errored=state1_is_errored, peer2_errored=state2_is_errored)
            return False
        state1_is_synced = state1.sync_manager.is_synced()
        state2_is_synced = state2.sync_manager.is_synced()
        if not state1_is_synced or not state2_is_synced:
            self.log.debug('peer not synced', peer1_synced=state1_is_synced, peer2_synced=state2_is_synced)
            return True
        return False

    def run_one_step(self, debug=False, force=False):
        assert self.is_connected, 'not connected'

        if debug:
            self.log.debug('conn step')

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
                    self.log.debug('[1->2] delivery delayed', latency=self.latency)
            else:
                self._proto2.dataReceived(line1)
                if debug:
                    self.log.debug('[1->2] delivered', line=line1)

        if line2:
            if self.latency > 0:
                self.manager2.reactor.callLater(self.latency, self._deliver_message, self._proto1, line2, debug)
                if debug:
                    self.log.debug('[2->1] delivery delayed', latency=self.latency)
            else:
                self._proto1.dataReceived(line2)
                if debug:
                    self.log.debug('[2->1] delivered', line=line2)

        if self.autoreconnect and self._proto1.aborting and self._proto2.aborting:
            self.reconnect()

        return True

    def run_until_empty(self, max_steps: Optional[int] = None, debug: bool = False, force: bool = False) -> None:
        """ Step until the connection reports as empty, optionally raise an assert if it takes more than `max_steps`.
        """
        steps = 0
        while not self.is_empty():
            steps += 1
            if max_steps is not None and steps > max_steps:
                raise AssertionError('took more steps than expected')
            self.run_one_step(debug=debug, force=force)
        self.log.debug('conn empty', steps=steps)

    def _deliver_message(self, proto, data, debug=False):
        proto.dataReceived(data)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self._proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self._proto2.connectionLost(reason)
        self.is_connected = False

    def reconnect(self) -> None:
        from twisted.python.failure import Failure
        if self.is_connected:
            self.disconnect(Failure(Exception('forced reconnection')))
        self._buf1.clear()
        self._buf2.clear()
        self._proto1 = self.manager1.connections.server_factory.buildProtocol(HostnameAddress(b'fake', 0))
        self._proto2 = self.manager2.connections.client_factory.buildProtocol(HostnameAddress(b'fake', 0))
        self.tr1 = HathorStringTransport(self._proto2.my_peer)
        self.tr2 = HathorStringTransport(self._proto1.my_peer)
        self._proto1.makeConnection(self.tr1)
        self._proto2.makeConnection(self.tr2)
        self.is_connected = True

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
