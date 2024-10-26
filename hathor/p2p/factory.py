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

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ClientFactory, Factory, ServerFactory

from hathor.p2p import P2PDependencies
from hathor.p2p.dependencies.protocols import P2PConnectionProtocol, P2PManagerProtocol
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.protocol import HathorLineReceiver


class _HathorLineReceiverFactory(ABC, Factory):
    inbound: bool

    def __init__(
        self,
        my_peer: PrivatePeer,
        p2p_manager: P2PManagerProtocol,
        *,
        dependencies: P2PDependencies,
        use_ssl: bool,
        build_protocol_callback: Callable[[IPv4Address | IPv6Address, P2PConnectionProtocol], None] | None,
    ):
        super().__init__()
        self.my_peer = my_peer
        self.p2p_manager = p2p_manager
        self.dependencies = dependencies
        self.use_ssl = use_ssl
        self._build_protocol_callback = build_protocol_callback

    def buildProtocol(self, addr: IAddress) -> HathorLineReceiver:
        assert isinstance(addr, (IPv4Address, IPv6Address))
        protocol = HathorLineReceiver(
            my_peer=self.my_peer,
            p2p_manager=self.p2p_manager,
            dependencies=self.dependencies,
            use_ssl=self.use_ssl,
            inbound=self.inbound,
            addr=addr,
        )
        if self._build_protocol_callback:
            self._build_protocol_callback(addr, protocol)
        return protocol


class HathorServerFactory(_HathorLineReceiverFactory, ServerFactory):
    """ HathorServerFactory is used to generate HathorProtocol objects when a new connection arrives.
    """
    inbound = True


class HathorClientFactory(_HathorLineReceiverFactory, ClientFactory):
    """ HathorClientFactory is used to generate HathorProtocol objects when we connected to another peer.
    """
    inbound = False
