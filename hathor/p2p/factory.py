# encoding: utf-8

from twisted.internet import protocol


from hathor.p2p.protocol import HathorLineReceiver
MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorServerFactory(protocol.ServerFactory):
    """ HathorServerFactory is used to generate HathorProtocol objects when
    a new connection arrives.

    :param manager: manager object
    :type manager: :class:`hathor.p2p.manager.Manager`
    """

    protocol = MyServerProtocol

    def __init__(self, network, my_peer, connections=None, node=None):
        """
        :type network: string
        :type my_peer: PeerId
        :type connections: ConnectionsManager
        :type node: HathorManager
        """
        super().__init__()
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

    def buildProtocol(self, addr):
        p = self.protocol(
            network=self.network,
            my_peer=self.my_peer,
            connections=self.connections,
            node=self.node,
        )
        p.factory = self
        return p


class HathorClientFactory(protocol.ClientFactory):

    """ HathorClientFactory is used to generate HathorProtocol objects when
    we connected to another peer.

    :param manager: manager object
    :type manager: :class:`hathor.p2p.manager.Manager`
    """

    protocol = MyClientProtocol

    def __init__(self, network, my_peer, connections=None, node=None):
        """
        :type network: string
        :type my_peer: PeerId
        :type connections: ConnectionsManager
        :type node: HathorManager
        """
        super().__init__()
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

    def buildProtocol(self, addr):
        p = self.protocol(
            network=self.network,
            my_peer=self.my_peer,
            connections=self.connections,
            node=self.node,
        )
        p.factory = self
        return p
