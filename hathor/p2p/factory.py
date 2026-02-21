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

from abc import ABC

from twisted.internet import protocol
from twisted.internet.interfaces import IAddress

from hathor.conf.settings import HathorSettings
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.protocol import HathorLineReceiver


class _HathorLineReceiverFactory(ABC, protocol.Factory):
    connection_type: HathorLineReceiver.ConnectionType
    def __init__(
        self,
        my_peer: PrivatePeer,
        p2p_manager: ConnectionsManager,
        *,
        settings: HathorSettings,
        use_ssl: bool,
    ):
        super().__init__()
        self._settings = settings
        self.my_peer = my_peer
        self.p2p_manager = p2p_manager
        self.use_ssl = use_ssl

    def buildProtocol(self, addr: IAddress) -> HathorLineReceiver:
        p = HathorLineReceiver(
            my_peer=self.my_peer,
            p2p_manager=self.p2p_manager,
            use_ssl=self.use_ssl,
            connection_type=self.connection_type,
            settings=self._settings
        )
        p.factory = self
        return p


class HathorServerFactory(_HathorLineReceiverFactory, protocol.ServerFactory):
    """ HathorServerFactory is used to generate HathorProtocol objects when a new connection arrives.
    """
    connection_type = HathorLineReceiver.ConnectionType.INCOMING


class HathorClientFactory(_HathorLineReceiverFactory, protocol.ClientFactory):
    """ HathorClientFactory is used to generate HathorProtocol objects when we connected to another peer.
    """
    connection_type = HathorLineReceiver.ConnectionType.OUTGOING


class HathorDiscoveredFactory(_HathorLineReceiverFactory, protocol.ClientFactory):
    """
        HathorDiscoveredFactory is the same as a HathorClientFactory, but the type of connection is set to
        discovered, for connection pool slotting.
    """
    connection_type = HathorLineReceiver.ConnectionType.DISCOVERED
