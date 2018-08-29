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
    parser.add_argument('--dns', action='append', help='Seeds DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', help='Address to listen for new connections (ex: 0.0.0.0:8000)')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to')
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

    factory = HathorFactory(peer_id)
    factory.startFactory()

    if args.dns:
        for host in args.dns:
            factory.dns_seed_lookup(host)

    if args.listen:
        host, port = args.listen.split(':')
        factory.listen(host, port)
        print('Listening to: {}:{}...'.format(host, port))

    if args.bootstrap:
        for address in args.bootstrap:
            host, port = address.split(':')
            print('Connecting to: {}:{}...'.format(host, int(port)))
            factory.connect_to(host, int(port))

    if args.status:
        status_server = server.Site(StatusResource(factory))
        reactor.listenTCP(args.status, status_server)

    reactor.run()
