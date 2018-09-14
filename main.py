# encoding: utf-8

from twisted.internet import reactor
from twisted.web import server
from twisted.python import log
from twisted.web.resource import Resource
from autobahn.twisted.resource import WebSocketResource

from hathor.p2p.peer_id import PeerId
from hathor.p2p.resources import StatusResource, MiningResource
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.p2p.manager import HathorManager
from hathor.transaction.storage import TransactionJSONStorage, TransactionMemoryStorage
from hathor.wallet.resources import BalanceResource, HistoryResource, AddressResource, \
                                    SendTokensResource, AuthWalletResource
from hathor.wallet import Wallet
from hathor.transaction.resources import DecodeTxResource, PushTxResource, GraphvizResource, TransactionResource
from hathor.websocket import HathorAdminWebsocketFactory
import hathor

import argparse
import getpass
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
    parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
    args = parser.parse_args()

    log.startLogging(sys.stdout)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('Hathor v{}'.format(hathor.__version__))
    print('My peer id is', peer_id.id)

    if args.data:
        tx_dir = os.path.join(args.data, 'tx')
        wallet_dir = args.data
        tx_storage = TransactionJSONStorage(path=tx_dir)
        wallet = Wallet(directory=wallet_dir)
        print('Using TransactionJSONStorage at {}'.format(tx_dir))
        print('Using Wallet at {}'.format(wallet_dir))
    else:
        tx_storage = TransactionMemoryStorage()
        wallet = Wallet()
        print('Using TransactionMemoryStorage')

    if args.unlock_wallet:
        wallet_passwd = getpass.getpass(prompt='Wallet password:')
        wallet.unlock(wallet_passwd)

    network = 'testnet'
    server_factory = HathorServerFactory()
    client_factory = HathorClientFactory()

    manager = HathorManager(server_factory, client_factory, peer_id=peer_id, network=network,
                            hostname=args.hostname, tx_storage=tx_storage, wallet=wallet)
    manager.doStart()

    if args.testnet:
        manager.dns_seed_lookup_text('testnet.hathor.network')

    if args.dns:
        for host in args.dns:
            manager.dns_seed_lookup(host)

    if args.listen:
        for description in args.listen:
            manager.listen(description)

    if args.bootstrap:
        for description in args.bootstrap:
            manager.connect_to(description)

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
            (b'balance', BalanceResource(manager), wallet_resource),
            (b'history', HistoryResource(manager), wallet_resource),
            (b'address', AddressResource(manager), wallet_resource),
            (b'send_tokens', SendTokensResource(manager), wallet_resource),
            (b'auth', AuthWalletResource(manager), wallet_resource),
        )
        for url_path, resource, parent in resources:
            parent.putChild(url_path, resource)

        # Websocket resource
        ws_factory = HathorAdminWebsocketFactory()
        resource = WebSocketResource(ws_factory)
        root.putChild(b"ws", resource)

        ws_factory.subscribe(manager.pubsub)

        status_server = server.Site(root)
        reactor.listenTCP(args.status, status_server)

    reactor.run()
