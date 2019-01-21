from typing import TYPE_CHECKING, Optional, Tuple

from twisted.internet import protocol

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.protocol import HathorLineReceiver

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401

MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver


class HathorServerFactory(protocol.ServerFactory):
    """ HathorServerFactory is used to generate HathorProtocol objects when a new connection arrives.
    """

    manager: Optional[ConnectionsManager]
    protocol = MyServerProtocol

    def __init__(
            self,
            network: str,
            my_peer: PeerId,
            connections: Optional[ConnectionsManager] = None,
            *,
            node: 'HathorManager',
    ):
        super().__init__()
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

    def buildProtocol(self, addr: Tuple[str, int]) -> MyServerProtocol:
        p = self.protocol(
            network=self.network,
            my_peer=self.my_peer,
            connections=self.connections,
            node=self.node,
        )
        p.factory = self
        return p


class HathorClientFactory(protocol.ClientFactory):
    """ HathorClientFactory is used to generate HathorProtocol objects when we connected to another peer.
    """

    manager: Optional[ConnectionsManager]
    protocol = MyClientProtocol

    def __init__(
            self,
            network: str,
            my_peer: PeerId,
            connections: Optional[ConnectionsManager] = None,
            *,
            node: 'HathorManager',
    ):
        super().__init__()
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

    def buildProtocol(self, addr: Tuple[str, int]) -> MyClientProtocol:
        p = self.protocol(
            network=self.network,
            my_peer=self.my_peer,
            connections=self.connections,
            node=self.node,
        )
        p.factory = self
        return p
