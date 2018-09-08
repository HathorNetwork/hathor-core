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
    manager = None

    def buildProtocol(self, addr):
        return self.protocol(self, self.manager)


class HathorClientFactory(protocol.ClientFactory):
    """ HathorClientFactory is used to generate HathorProtocol objects when
    we connected to another peer.

    :param manager: manager object
    :type manager: :class:`hathor.p2p.manager.Manager`
    """

    protocol = MyServerProtocol
    manager = None

    def buildProtocol(self, addr):
        return self.protocol(self, self.manager)
