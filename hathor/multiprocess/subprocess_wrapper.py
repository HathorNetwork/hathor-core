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

from structlog import get_logger
from twisted.internet.interfaces import IAddress, IProtocol
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.python.failure import Failure

from hathor.multiprocess.utils import log_connection_closed
from hathor.reactor import ReactorProtocol

logger = get_logger()


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
        super().connectionLost(reason)
        if not self.reactor.running:
            return

        log_connection_closed(log=self.log, reason=reason, message='connection lost, stopping subprocess reactor')
        self.reactor.stop()


class SubprocessWrappingFactory(WrappingFactory):
    __slots__ = ('log', 'reactor', '_addr_str')

    def __init__(self, *, reactor: ReactorProtocol, addr_str: str, wrapped_factory: Factory) -> None:
        super().__init__(wrapped_factory)
        self.log = logger.new(addr=addr_str, subprocess_pid=os.getpid())
        self.reactor = reactor
        self._addr_str = addr_str

    def buildProtocol(self, addr: IAddress) -> Protocol | None:
        assert self._addr_str == str(addr)
        self.log.debug('building protocol for subprocess wrapper')
        wrapped_protocol = self.wrappedFactory.buildProtocol(addr)
        return SubprocessProtocolWrapper(
            reactor=self.reactor,
            factory=self,
            addr_str=self._addr_str,
            wrapped_protocol=wrapped_protocol,
        )
