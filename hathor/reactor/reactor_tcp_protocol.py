#  Copyright 2023 Hathor Labs
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

from abc import abstractmethod
from typing import TYPE_CHECKING, Optional, Protocol

from twisted.internet.interfaces import IReactorTCP
from zope.interface import implementer

if TYPE_CHECKING:
    from twisted.internet.interfaces import IConnector, IListeningPort
    from twisted.internet.protocol import ClientFactory, ServerFactory


@implementer(IReactorTCP)
class ReactorTCPProtocol(Protocol):
    """
    A Python protocol that stubs Twisted's IReactorTCP interface.
    """

    @abstractmethod
    def listenTCP(
        self,
        port: int,
        factory: 'ServerFactory',
        backlog: int = 0,
        interface: str = ''
    ) -> 'IListeningPort':
        raise NotImplementedError

    @abstractmethod
    def connectTCP(
        self,
        host: str,
        port: int,
        factory: 'ClientFactory',
        timeout: float,
        bindAddress: Optional[tuple[str, int]],
    ) -> 'IConnector':
        raise NotImplementedError
