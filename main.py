# encoding: utf-8

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol
from twisted.internet import protocol, reactor
from twisted.python import log

from hathor.p2p.protocol import HathorLineReceiver
from hathor.p2p.peer_id import PeerId

import argparse
import sys
import json

MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver


class MyFactory(protocol.Factory):
    def __init__(self, peer_id):
        self.peer_id = peer_id
        super(MyFactory, self).__init__()

    def startFactory(self):
        self.connected_peers = {}

    def update_peers(self, peer, received_peers):
        for new_peer_id, new_peer_address in received_peers:
            if new_peer_id == self.peer_id.id:
                continue
            if new_peer_id not in self.connected_peers:
                host, port = new_peer_address.split(':')
                self.connect_to(host, port)

    def buildProtocol(self, addr):
        return MyServerProtocol(self)

    def connect_to(self, host, port):
        point = TCP4ClientEndpoint(reactor, host, port)
        connectProtocol(point, MyClientProtocol(self))

    def listen(self, host, port):
        endpoint = TCP4ServerEndpoint(reactor, int(port), interface=host)
        endpoint.listen(factory)
        self.peer_id.endpoints.append(endpoint)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', help='Address to listen for new connections (ex: 0.0.0.0:8000)')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to')
    args = parser.parse_args()

    log.startLogging(sys.stdout)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('My peer id is', peer_id.id)

    factory = MyFactory(peer_id)
    factory.startFactory()

    if args.listen:
        host, port = args.listen.split(':')
        factory.listen(host, port)
        print('Listening to: {}:{}...'.format(host, port))

    if args.bootstrap:
        for address in args.bootstrap:
            host, port = address.split(':')
            print('Connecting to: {}:{}...'.format(host, int(port)))
            factory.connect_to(host, int(port))

    reactor.run()
