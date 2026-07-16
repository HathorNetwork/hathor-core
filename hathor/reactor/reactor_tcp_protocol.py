# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
