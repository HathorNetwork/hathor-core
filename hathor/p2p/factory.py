# encoding: utf-8

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol
from twisted.internet import protocol, reactor
import twisted.names.client

from hathor.p2p.protocol import HathorLineReceiver

import time
import socket


MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorFactory(protocol.Factory):
    default_port = 40403

    def __init__(self, peer_id):
        self.peer_id = peer_id
        super(HathorFactory, self).__init__()

    def startFactory(self):
        self.connected_peers = {}
        self.start_time = time.time()

    def buildProtocol(self, addr):
        return MyServerProtocol(self)

    def update_peers(self, peer, received_peers):
        for new_peer_id, new_peer_address in received_peers:
            if new_peer_id == self.peer_id.id:
                continue
            if new_peer_id not in self.connected_peers:
                host, port = new_peer_address.split(':')
                self.connect_to(host, port)

    def connect_to(self, host, port):
        point = TCP4ClientEndpoint(reactor, host, port)
        print('Connecting to:', host, port)
        connectProtocol(point, MyClientProtocol(self))

    def listen(self, host, port):
        endpoint = TCP4ServerEndpoint(reactor, int(port), interface=host)
        endpoint.listen(self)
        self.peer_id.endpoints.append(endpoint)

    def dns_seed_lookup(self, host):
        x1 = twisted.names.client.lookupAddress(host)
        x1.addCallback(self.on_dns_seed_found_ipv4)
        # x2 = twisted.names.client.lookupIPV6Address(host)
        # x2.addCallback(self.on_dns_seed_found_ipv6)

    def on_dns_seed_found_ipv4(self, results):
        answers, _, _ = results
        for x in answers:
            address = x.payload.address
            host = socket.inet_ntoa(address)
            self.connect_to(host, self.default_port)

    # def on_dns_seed_found_ipv6(self, results):
    #     answers, _, _ = results
    #     for x in answers:
    #         address = x.payload.address
    #         host = socket.inet_ntop(socket.AF_INET6, address)
