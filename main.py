# encoding: utf-8

from twisted.internet import reactor
from twisted.web import server
from twisted.python import log

from hathor.p2p.peer_id import PeerId
from hathor.p2p.status import StatusResource
from hathor.p2p.factory import HathorFactory
import hathor

import argparse
import sys
import json


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor testnet')
    parser.add_argument('--dns', action='append', help='Seed DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', action='append', help='Address to listen for new connections (eg: tcp:8000)')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
    parser.add_argument('--status', type=int, help='Port to run status server')
    args = parser.parse_args()

    log.startLogging(sys.stdout)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('Hathor v{}'.format(hathor.__version__))
    print('My peer id is', peer_id.id)

    factory = HathorFactory(peer_id=peer_id, hostname=args.hostname)
    factory.startFactory()

    if args.testnet:
        factory.dns_seed_lookup_text('testnet.hathor.network')

    if args.dns:
        for host in args.dns:
            factory.dns_seed_lookup(host)

    if args.listen:
        for description in args.listen:
            factory.listen(description)

    if args.bootstrap:
        for description in args.bootstrap:
            factory.connect_to(description)

    if args.status:
        status_server = server.Site(StatusResource(factory))
        reactor.listenTCP(args.status, status_server)

    reactor.run()
