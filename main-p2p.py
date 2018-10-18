# encoding: utf-8

from twisted.internet import reactor
from twisted.python import log

from hathor.p2p.peer_id import PeerId
from hathor.p2p.process_manager import ProcessManager
from hathor.p2p.peer_discovery import DNSPeerDiscovery, BootstrapPeerDiscovery

import argparse
import sys
import json


def main(stringArgs):
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor testnet')
    parser.add_argument('--dns', action='append', help='Seed DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', action='append', help='Address to listen for new connections (eg: tcp:8000)')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
    parser.add_argument('--data', help='Data directory')
    args, unknown = parser.parse_known_args(stringArgs.split(' '))

    log.startLogging(sys.stdout)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('My peer id is', peer_id.id)

    if args.data:
        # tx_dir = os.path.join(args.data, 'tx')
        # tx_storage = TransactionJSONStorage(path=tx_dir)
        # print('Using TransactionJSONStorage at {}'.format(tx_dir))
        pass
    else:
        # tx_storage = TransactionMemoryStorage()
        # print('Using TransactionMemoryStorage')
        pass

    network = 'testnet'
    manager = ProcessManager(reactor, peer_id=peer_id, network=network, hostname=args.hostname)

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


if __name__ == '__main__':
    args = sys.argv[1:]
    main(' '.join(args))
