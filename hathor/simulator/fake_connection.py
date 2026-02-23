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

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Literal, Optional

from OpenSSL.crypto import X509
from structlog import get_logger
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.testing import StringTransport

from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.peer_id import PeerId

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.p2p.peer import PublicPeer

logger = get_logger()


class HathorStringTransport(StringTransport):
    def __init__(self, peer: PrivatePeer, *, peer_address: IPv4Address | IPv6Address):
        super().__init__(peerAddress=peer_address)
        self._peer = peer

    @property
    def peer(self) -> PublicPeer:
        return self._peer.to_public_peer()

    def getPeerCertificate(self) -> X509:
        assert isinstance(self._peer, PrivatePeer)
        return X509.from_cryptography(self._peer.certificate)


class FakeConnection:
    _next_port: int = 49000
    _port_per_manager: dict['HathorManager', int] = {}

    def __init__(
        self,
        manager1: 'HathorManager',
        manager2: 'HathorManager',
        *,
        latency: float = 0,
        autoreconnect: bool = False,
        addr1: IPv4Address | IPv6Address | None = None,
        addr2: IPv4Address | IPv6Address | None = None,
        fake_bootstrap_id: PeerId | None | Literal[False] = False,
    ):
        """
        :param: latency: Latency between nodes in seconds
        :fake_bootstrap_id: when False, bootstrap mode is disabled. When a PeerId or None are passed, bootstrap mode is
            enabled and the value is used as the connection's entrypoint.peer_id
        """
        self.log = logger.new()
        self._fake_bootstrap_id = fake_bootstrap_id

        self.manager1 = manager1
        self.manager2 = manager2

        self.latency = latency
        self.autoreconnect = autoreconnect
        self.is_connected = False

        self._do_buffering = True
        self._buf1: deque[str] = deque()
        self._buf2: deque[str] = deque()

        # manager1's address, the server, where manager2 will connect to
        self.addr1 = addr1 or IPv4Address('TCP', '127.0.0.1', self._get_port(manager1))
        # manager2's address, the client, where manager2 will connect from
        self.addr2 = addr2 or IPv4Address('TCP', '127.0.0.1', self._get_port(manager2))

        self.reconnect()

    @classmethod
    def _get_port(cls, manager: 'HathorManager') -> int:
        port = cls._port_per_manager.get(manager)
        if port is None:
            port = cls._next_port
            cls._next_port += 1
        return port

    @property
    def entrypoint(self) -> PeerEndpoint:
        entrypoint = PeerAddress.from_address(self.addr1)
        if self._fake_bootstrap_id is False:
            return entrypoint.with_id(self.manager1.my_peer.id)
        return entrypoint.with_id(self._fake_bootstrap_id)

    @property
    def peer_addr1(self) -> PeerAddress:
        return PeerAddress.from_address(self.addr1)

    @property
    def peer_addr2(self) -> PeerAddress:
        return PeerAddress.from_address(self.addr2)

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

    def is_both_synced(self, *, errmsgs: Optional[list[str]] = None) -> bool:
        """Short-hand check that can be used to make "step loops" without having to guess the number of iterations."""
        if errmsgs is None:
            errmsgs = []
        from hathor.p2p.states.ready import ReadyState
        conn1_aborting = self._proto1.aborting
        conn2_aborting = self._proto2.aborting
        if conn1_aborting or conn2_aborting:
            self.log.debug('conn aborting', conn1_aborting=conn1_aborting, conn2_aborting=conn2_aborting)
            errmsgs.append('conn aborting')
            return False
        state1 = self._proto1.state
        state2 = self._proto2.state
        state1_is_ready = isinstance(state1, ReadyState)
        state2_is_ready = isinstance(state2, ReadyState)
        if not state1_is_ready or not state2_is_ready:
            self.log.debug('peer not ready', peer1_ready=state1_is_ready, peer2_ready=state2_is_ready)
            errmsgs.append('peer not ready')
            return False
        assert isinstance(state1, ReadyState)  # mypy can't infer this from the above
        assert isinstance(state2, ReadyState)  # mypy can't infer this from the above
        state1_is_errored = state1.sync_agent.is_errored()
        state2_is_errored = state2.sync_agent.is_errored()
        if state1_is_errored or state2_is_errored:
            self.log.debug('peer errored', peer1_errored=state1_is_errored, peer2_errored=state2_is_errored)
            errmsgs.append('peer errored')
            return False
        state1_is_synced = state1.sync_agent.is_synced()
        state2_is_synced = state2.sync_agent.is_synced()
        if not state1_is_synced or not state2_is_synced:
            self.log.debug('peer not synced', peer1_synced=state1_is_synced, peer2_synced=state2_is_synced)
            errmsgs.append('peer not synced')
            return False
        [best_block_info1] = state1.protocol.node.tx_storage.get_n_height_tips(1)
        [best_block_info2] = state2.protocol.node.tx_storage.get_n_height_tips(1)
        if best_block_info1.id != best_block_info2.id:
            self.log.debug('best block is different')
            errmsgs.append('best block is different')
            return False
        tips1 = {tx.hash for tx in state1.protocol.node.tx_storage.iter_mempool_tips()}
        tips2 = {tx.hash for tx in state2.protocol.node.tx_storage.iter_mempool_tips()}
        if tips1 != tips2:
            self.log.debug('tx tips are different')
            errmsgs.append('tx tips are different')
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
        state1_is_errored = state1.sync_agent.is_errored()
        state2_is_errored = state2.sync_agent.is_errored()
        if state1_is_errored or state2_is_errored:
            self.log.debug('peer errored', peer1_errored=state1_is_errored, peer2_errored=state2_is_errored)
            return False
        state1_is_synced = state1.sync_agent.is_synced()
        state2_is_synced = state2.sync_agent.is_synced()
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

        self._proto1 = self.manager1.connections.server_factory.buildProtocol(self.addr2)
        self._proto2 = self.manager2.connections.client_factory.buildProtocol(self.addr1)

        # When _fake_bootstrap_id is set we don't pass the peer because that's how bootstrap calls connect_to()
        peer = self._proto1.my_peer.to_unverified_peer() if self._fake_bootstrap_id is False else None
        deferred = self.manager2.connections.connect_to(self.entrypoint, peer)
        assert deferred is not None
        deferred.callback(self._proto2)

        self.tr1 = HathorStringTransport(self._proto2.my_peer, peer_address=self.addr2)
        self.tr2 = HathorStringTransport(self._proto1.my_peer, peer_address=self.addr1)
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
