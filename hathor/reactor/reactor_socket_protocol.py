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

from socket import AddressFamily
from typing import Protocol

from twisted.internet.interfaces import IListeningPort, IReactorSocket
from twisted.internet.protocol import DatagramProtocol, ServerFactory
from zope.interface import implementer


@implementer(IReactorSocket)
class ReactorSocketProtocol(Protocol):
    """A Python protocol that stubs Twisted's IReactorSocket interface."""

    def adoptStreamPort(
        self,
        fileDescriptor: int,
        addressFamily: AddressFamily,
        factory: ServerFactory,
    ) -> IListeningPort:
        ...

    def adoptStreamConnection(self, fileDescriptor: int, addressFamily: AddressFamily, factory: ServerFactory) -> None:
        ...

    def adoptDatagramPort(
        self,
        fileDescriptor: int,
        addressFamily: AddressFamily,
        protocol: DatagramProtocol,
        maxPacketSize: int,
    ) -> IListeningPort:
        ...
