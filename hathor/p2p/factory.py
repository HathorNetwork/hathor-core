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
from typing import Callable

from twisted.internet import protocol
from twisted.internet.interfaces import IAddress

from hathor.p2p import P2PDependencies
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.protocol import HathorLineReceiver, HathorProtocol


class _HathorLineReceiverFactory(ABC, protocol.Factory):
    inbound: bool

    def __init__(
        self,
        my_peer: PrivatePeer,
        p2p_manager: ConnectionsManager,
        *,
        dependencies: P2PDependencies,
        use_ssl: bool,
        built_protocol_callback: Callable[[PeerAddress, HathorProtocol], None] | None,
    ):
        super().__init__()
        self.my_peer = my_peer
        self.p2p_manager = p2p_manager
        self.dependencies = dependencies
        self.use_ssl = use_ssl
        self._built_protocol_callback = built_protocol_callback

    def buildProtocol(self, addr: IAddress) -> HathorLineReceiver:
        peer_addr = PeerAddress.from_address(addr)
        hathor_protocol = HathorLineReceiver(
            addr=peer_addr,
            my_peer=self.my_peer,
            p2p_manager=self.p2p_manager,
            dependencies=self.dependencies,
            use_ssl=self.use_ssl,
            inbound=self.inbound,
        )
        if self._built_protocol_callback:
            self._built_protocol_callback(peer_addr, hathor_protocol)
        return hathor_protocol


class HathorServerFactory(_HathorLineReceiverFactory, protocol.ServerFactory):
    """ HathorServerFactory is used to generate HathorProtocol objects when a new connection arrives.
    """
    inbound = True


class HathorClientFactory(_HathorLineReceiverFactory, protocol.ClientFactory):
    """ HathorClientFactory is used to generate HathorProtocol objects when we connected to another peer.
    """
    inbound = False
