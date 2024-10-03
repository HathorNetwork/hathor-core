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

from typing import TYPE_CHECKING, Optional

from twisted.internet import protocol
from twisted.internet.interfaces import IAddress

from hathor.conf.settings import HathorSettings
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import Peer
from hathor.p2p.protocol import HathorLineReceiver
from hathor.reactor import ReactorProtocol

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401


class SyncFactory(protocol.ServerFactory):
    """
    SyncFactory is used to generate HathorProtocol objects for new connections for both clients and servers,
    depending on the inbound parameter.
    """

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        manager: HathorManager,
        connections: ConnectionsManager,
        my_peer: Peer,
        my_capabilities: list[str],
        use_ssl: bool,
        inbound: bool,
    ) -> None:
        super().__init__()
        self.reactor = reactor
        self._settings = settings
        self.manager = manager
        self.connections = connections
        self.my_peer = my_peer
        self.my_capabilities = my_capabilities
        self.use_ssl = use_ssl
        self.inbound = inbound

    def buildProtocol(self, addr: IAddress) -> HathorLineReceiver:
        p = HathorLineReceiver(
            reactor=self.reactor,
            settings=self._settings,
            manager=self.manager,
            connections=self.connections,
            my_peer=self.my_peer,
            my_capabilities=self.my_capabilities,
            use_ssl=self.use_ssl,
            inbound=self.inbound,
        )
        p.factory = self
        return p
