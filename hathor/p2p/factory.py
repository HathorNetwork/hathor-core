# encoding: utf-8

from twisted.internet import protocol, reactor, endpoints
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
    def __init__(self, peer_id, default_port=40403):
        self.peer_id = peer_id
        self.default_port = default_port
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

    def connect_to(self, description):
        endpoint = self.clientFromString(description)
        endpoint.connect(self)
        print('Connecting to: {}...'.format(description))

    def serverFromString(self, description):
        return endpoints.serverFromString(reactor, description)

    def listen(self, description):
        endpoint = self.serverFromString(description)
        endpoint.listen(self)
        print('Listening to: {}...'.format(description))

    def dns_seed_lookup_text(self, host):
        x = twisted.names.client.lookupText(host)
        x.addCallback(self.on_dns_seed_found)

    def dns_seed_lookup_address(self, host):
        x = twisted.names.client.lookupAddress(host)
        x.addCallback(self.on_dns_seed_found_ipv4)

    def dns_seed_lookup_ipv6_address(self, host):
        x = twisted.names.client.lookupIPV6Address(host)
        x.addCallback(self.on_dns_seed_found_ipv6)

    def dns_seed_lookup(self, host):
        self.dns_seed_lookup_text(host)
        self.dns_seed_lookup_address(host)
        # self.dns_seed_lookup_ipv6_address(host)

    def clientFromString(self, description):
        return endpoints.clientFromString(reactor, description)

    def on_dns_seed_found(self, results):
        answers, _, _ = results
        for x in answers:
            data = x.payload.data
            for txt in data:
                txt = txt.decode('utf-8')
                try:
                    print('Seed DNS TXT: "{}" found'.format(txt))
                    endpoint = self.clientFromString(txt)
                    endpoint.connect(self)
                except ValueError:
                    print('Seed DNS TXT: Error parsing "{}"'.format(txt))

    def on_dns_seed_found_ipv4(self, results):
        answers, _, _ = results
        for x in answers:
            address = x.payload.address
            host = socket.inet_ntoa(address)
            self.connect_to('tcp:{}:{}'.format(host, self.default_port))
            print('Seed DNS A: "{}" found'.format(host))

    def on_dns_seed_found_ipv6(self, results):
        # answers, _, _ = results
        # for x in answers:
        #     address = x.payload.address
        #     host = socket.inet_ntop(socket.AF_INET6, address)
        raise NotImplemented()
