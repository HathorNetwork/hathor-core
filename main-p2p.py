# encoding: utf-8

from twisted.internet import reactor
from twisted.python import log

from hathor.p2p.peer_id import PeerId
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_discovery import DNSPeerDiscovery, BootstrapPeerDiscovery
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.p2p.manager import NetworkManager

import argparse
import sys
import json
import os


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor testnet')
    parser.add_argument('--dns', action='append', help='Seed DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', action='append', help='Address to listen for new connections (eg: tcp:8000)')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
    parser.add_argument('--data', help='Data directory')
    args, unknown = parser.parse_known_args()

    log.startLogging(sys.stdout)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('My peer id is', peer_id.id)

    if args.data:
        unix_socket = os.path.join(args.data, 'hathor.sock')
    else:
        unix_socket = '/tmp/hathor.sock'

    network = 'testnet'

    manager = NetworkManager(reactor, peer_id=peer_id, hostname=args.hostname, unix_socket=unix_socket)

    dns_hosts = []
    if args.testnet:
        dns_hosts.append('testnet.hathor.network')
    if args.dns:
        dns_hosts.extend(dns_hosts)

    if dns_hosts:
        manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))
    if args.bootstrap:
        manager.add_peer_discovery(BootstrapPeerDiscovery(args.bootstrap))

    manager.start()

    if args.listen:
        for description in args.listen:
            manager.listen(description)

    reactor.run()
