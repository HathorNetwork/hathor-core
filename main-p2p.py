# encoding: utf-8

from twisted.internet import reactor
from twisted.python import log
from twisted.web import server
from twisted.web.resource import Resource
from autobahn.twisted.resource import WebSocketResource

from hathor.p2p.peer_id import PeerId
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_discovery import DNSPeerDiscovery, BootstrapPeerDiscovery
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.p2p.manager import NetworkManager
from hathor.websocket import HathorAdminWebsocketFactory
from hathor.resources import ProfilerResource
from hathor.wallet.resources import BalanceResource, HistoryResource, AddressResource, \
                                    SendTokensResource, UnlockWalletResource, \
                                    LockWalletResource, StateWalletResource
from hathor.p2p.resources import StatusResource, MiningResource
from hathor.transaction.resources import DecodeTxResource, PushTxResource, GraphvizResource, \
                                        TransactionResource, DashboardTransactionResource

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
    parser.add_argument('--status', type=int, help='Port to run status server')
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

    if args.status:
        # TODO get this from a file. How should we do with the factory?
        root = Resource()
        wallet_resource = Resource()
        root.putChild(b'wallet', wallet_resource)

        resources = (
            (b'status', StatusResource(manager), root),
            (b'mining', MiningResource(manager), root),
            (b'decode_tx', DecodeTxResource(manager), root),
            (b'push_tx', PushTxResource(manager), root),
            (b'graphviz', GraphvizResource(manager), root),
            (b'transaction', TransactionResource(manager), root),
            (b'dashboard_tx', DashboardTransactionResource(manager), root),
            (b'profiler', ProfilerResource(manager), root),
            (b'balance', BalanceResource(manager), wallet_resource),
            (b'history', HistoryResource(manager), wallet_resource),
            (b'address', AddressResource(manager), wallet_resource),
            (b'send_tokens', SendTokensResource(manager), wallet_resource),
            (b'unlock', UnlockWalletResource(manager), wallet_resource),
            (b'lock', LockWalletResource(manager), wallet_resource),
            (b'state', StateWalletResource(manager), wallet_resource),
        )
        for url_path, resource, parent in resources:
            parent.putChild(url_path, resource)

        # Websocket resource
        ws_factory = HathorAdminWebsocketFactory(manager)
        resource = WebSocketResource(ws_factory)
        root.putChild(b"ws", resource)

        ws_factory.subscribe(manager.pubsub)

        status_server = server.Site(root)
        reactor.listenTCP(args.status, status_server)

    reactor.run()
