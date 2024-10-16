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
from typing import Any

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols import amp

from hathor.p2p import P2PManager


class Start(amp.Command):
    pass


class P2PIpcServer(amp.AMP):
    __slots__ = ('_p2p_manager',)

    def __init__(self, *, p2p_manager: P2PManager) -> None:
        super().__init__()
        self._p2p_manager = p2p_manager

    @Start.responder
    async def start(self) -> dict[str, Any]:
        await self._p2p_manager.start()
        return {}


class P2PIpcServerFactory(ServerFactory):
    __slots__ = ('_p2p_manager',)

    def __init__(self, *, p2p_manager: P2PManager) -> None:
        self._p2p_manager = p2p_manager

    def buildProtocol(self, addr: IAddress) -> P2PIpcServer:
        p = P2PIpcServer(p2p_manager=self._p2p_manager)
        p.factory = self
        return p
