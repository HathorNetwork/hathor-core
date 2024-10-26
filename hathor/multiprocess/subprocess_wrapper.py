#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
from twisted.internet.address import IPv4Address, IPv6Address

from structlog import get_logger
from twisted.internet.interfaces import IAddress, IProtocol
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.python.failure import Failure

from hathor.multiprocess.utils import log_connection_closed, addr_to_str
from hathor.p2p.multiprocess.remote_ipc import RemoteIpcServer, IpcProxyType
from hathor.reactor import ReactorProtocol

logger = get_logger()


def get_subprocess_protocol_server_addr(addr: IPv4Address | IPv6Address | str) -> str:
    addr_str = addr_to_str(addr) if isinstance(addr, (IPv4Address, IPv6Address)) else addr
    return f'/tmp/p2p_connection:{addr_str}.sock'


class SubprocessProtocolWrapper(ProtocolWrapper):
    __slots__ = ('log', 'reactor' '_addr_str')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        factory: WrappingFactory,
        addr_str: str,
        wrapped_protocol: IProtocol,
    ) -> None:
        super().__init__(factory, wrapped_protocol)
        self.log = logger.new(addr=addr_str, subprocess_pid=os.getpid())
        self.reactor = reactor
        self._addr_str = addr_str

    def connectionMade(self) -> None:
        self.log.debug('subprocess connection made')
        super().connectionMade()

    def dataReceived(self, data: bytes) -> None:
        self.log.debug('data received', data=data)
        super().dataReceived(data)

    def connectionLost(self, reason: Failure) -> None:  # type: ignore[override]
        try:
            super().connectionLost(reason)
        except Exception:
            self.log.exception('exception while calling wrapped connectionLost')

        if self.reactor.running:
            self.reactor.stop()

        log_connection_closed(log=self.log, reason=reason, message='connection lost, stopping subprocess')


class SubprocessWrappingFactory(WrappingFactory):
    __slots__ = ('log', 'reactor', '_addr_str', '_built_protocol')

    def __init__(self, *, reactor: ReactorProtocol, addr_str: str, wrapped_factory: Factory) -> None:
        super().__init__(wrapped_factory)
        self.log = logger.new(addr=addr_str, subprocess_pid=os.getpid())
        self.reactor = reactor
        self._addr_str = addr_str
        self._built_protocol = False

    def buildProtocol(self, addr: IAddress) -> Protocol | None:
        assert not self._built_protocol, 'there must be only one subprocess protocol per factory'
        assert self._addr_str == str(addr)
        self.log.debug('building protocol for subprocess wrapper')

        try:
            wrapped_protocol = self.wrappedFactory.buildProtocol(addr)
        except Exception:
            self.log.exception('exception while calling wrapped buildProtocol')
            if self.reactor.running:
                self.reactor.stop()
            return None

        protocol_server = RemoteIpcServer(
            reactor=self.reactor,
            proxy_type=IpcProxyType.P2P_CONNECTION,  # TODO: This class shouldn't know anything about P2P, improve this
            proxy_obj=wrapped_protocol,
        )
        protocol_server.start()  # TODO: Move somewhere else.

        self._built_protocol = True
        return SubprocessProtocolWrapper(
            reactor=self.reactor,
            factory=self,
            addr_str=self._addr_str,
            wrapped_protocol=wrapped_protocol,
        )
