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

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401


class SyncFactory(protocol.ServerFactory):
    manager: Optional[ConnectionsManager]

    def __init__(
        self,
        network: str,
        my_peer: Peer,
        p2p_manager: ConnectionsManager,
        *,
        settings: HathorSettings,
        use_ssl: bool,
        inbound: bool,
    ):
        super().__init__()
        self._settings = settings
        self.network = network
        self.my_peer = my_peer
        self.p2p_manager = p2p_manager
        self.use_ssl = use_ssl
        self.inbound = inbound

    def buildProtocol(self, addr: IAddress) -> HathorLineReceiver:
        assert self.protocol is not None
        p = HathorLineReceiver(
            reactor=self.p2p_manager.reactor,
            settings=self._settings,
            my_peer=self.my_peer,
            client=None,
            use_ssl=self.use_ssl,
            inbound=self.inbound,
        )
        p.factory = self
        return p
