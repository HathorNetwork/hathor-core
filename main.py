# encoding: utf-8

from twisted.internet import reactor
from twisted.web import server
from twisted.python import log
from twisted.web.resource import Resource
from autobahn.twisted.resource import WebSocketResource

from hathor.p2p.resources import StatusResource, MiningResource
from hathor.manager import HathorManager
from hathor.transaction.storage import TransactionJSONStorage, TransactionMemoryStorage
from hathor.wallet.resources import BalanceResource, HistoryResource, AddressResource, \
                                    SendTokensResource, UnlockWalletResource, \
                                    LockWalletResource, StateWalletResource
from hathor.resources import ProfilerResource
from hathor.wallet import Wallet, HDWallet
from hathor.transaction.resources import DecodeTxResource, PushTxResource, GraphvizResource, \
                                        TransactionResource, DashboardTransactionResource
from hathor.websocket import HathorAdminWebsocketFactory
import hathor

import argparse
import getpass
import sys
import os


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--status', type=int, help='Port to run status server')
    parser.add_argument('--data', help='Data directory')
    parser.add_argument(
        '--wallet',
        help='Set wallet type. Options are hd (Hierarchical Deterministic) or keypair',
        default='hd'
    )
    parser.add_argument('--words', help='Words used to generate the seed for HD Wallet')
    parser.add_argument('--listen', action='append', help='Address to listen for new connections (eg: tcp:8000)')
    parser.add_argument('--passphrase', action='store_true', help='Passphrase used to generate the seed for HD Wallet')
    parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
    args, unknown = parser.parse_known_args()

    log.startLogging(sys.stdout)

    print('Hathor v{}'.format(hathor.__version__))

    def create_wallet():
        if args.wallet == 'hd':
            kwargs = {
                'words': args.words,
            }

            if args.passphrase:
                wallet_passphrase = getpass.getpass(prompt='HD Wallet passphrase:')
                kwargs['passphrase'] = wallet_passphrase.encode()

            if args.data:
                kwargs['directory'] = args.data

            return HDWallet(**kwargs)
        elif args.wallet == 'keypair':
            if args.data:
                wallet = Wallet(directory=args.data)
            else:
                wallet = Wallet()

            wallet.flush_to_disk_interval = 5  # seconds

            if args.unlock_wallet:
                wallet_passwd = getpass.getpass(prompt='Wallet password:')
                wallet.unlock(wallet_passwd.encode())

            return wallet
        else:
            raise ValueError('Invalid type for wallet')

    if args.data:
        tx_dir = os.path.join(args.data, 'tx')
        wallet_dir = args.data
        tx_storage = TransactionJSONStorage(path=tx_dir)
        print('Using TransactionJSONStorage at {}'.format(tx_dir))
        print('Using Wallet at {}'.format(wallet_dir))
        # unix socket
        unix_socket = os.path.join(args.data, 'hathor.sock')
    else:
        tx_storage = TransactionMemoryStorage()
        print('Using TransactionMemoryStorage')
        # unix socket
        unix_socket = '/tmp/hathor.sock'

    wallet = create_wallet()

    manager = HathorManager(reactor, tx_storage=tx_storage, wallet=wallet, unix_socket=unix_socket)
    manager.start()

    if args.listen:
        # start subprocess to handle p2p
        newpid = os.fork()
        if newpid == 0:
            # new_args should be a list like ['python', 'main-p2p.py', arg1, arg2, ...]
            new_args = [sys.executable, 'main-p2p.py']
            new_args.extend(sys.argv[1:])
            os.execv(sys.executable, new_args)

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
        ws_factory = HathorAdminWebsocketFactory(metrics=manager.metrics)
        resource = WebSocketResource(ws_factory)
        root.putChild(b"ws", resource)

        ws_factory.subscribe(manager.pubsub)

        status_server = server.Site(root)
        reactor.listenTCP(args.status, status_server)

    reactor.run()
