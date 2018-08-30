# encoding: utf-8

from twisted.internet import protocol, reactor, endpoints
import twisted.names.client

from hathor.p2p.protocol import HathorLineReceiver
from hathor.p2p.peer_storage import PeerStorage

import time
import socket
import random


MyServerProtocol = HathorLineReceiver
MyClientProtocol = HathorLineReceiver

# from hathor.p2p.protocol import HathorWebSocketServerProtocol, HathorWebSocketClientProtocol
# MyServerProtocol = HathorWebSocketServerProtocol
# MyClientProtocol = HathorWebSocketClientProtocol


class HathorFactory(protocol.Factory):
    def __init__(self, peer_id, hostname=None, peer_storage=None, default_port=40403):
        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.peer_storage = peer_storage or PeerStorage()

        self.my_peer = peer_id
        self.default_port = default_port
        super(HathorFactory, self).__init__()

    def startFactory(self):
        self.connected_peers = {}
        self.start_time = time.time()

    def buildProtocol(self, addr):
        return MyServerProtocol(self)

    def update_peer(self, peer):
        if peer.id == self.my_peer.id:
            return
        self.peer_storage.add_or_merge(peer)
        self.connect_to_if_not_connected(peer)

    def connect_to_if_not_connected(self, peer):
        if not peer.entrypoints:
            return
        if peer.id not in self.connected_peers:
            self.connect_to(random.choice(peer.entrypoints))

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
        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)

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
