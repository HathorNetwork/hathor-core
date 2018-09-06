# encoding: utf-8

from twisted.internet import protocol


from hathor.p2p.protocol import HathorLineReceiver
MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorFactory(protocol.Factory):
    """ HathorFactory is used to generate HathorProtocol objects.
    """

    protocol = MyServerProtocol

    def buildProtocol(self, addr):
        return self.protocol(self)
