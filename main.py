# encoding: utf-8

from twisted.internet import reactor
from twisted.web import server
from twisted.python import log

from hathor.manager import HathorManager
from hathor.transaction.storage import TransactionJSONStorage, TransactionMemoryStorage
from hathor.wallet import Wallet, HDWallet
from hathor.prometheus import PrometheusMetricsExporter
import hathor

import argparse
import getpass
import sys
import os


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', help='Data directory')
    parser.add_argument(
        '--wallet',
        help='Set wallet type. Options are hd (Hierarchical Deterministic) or keypair',
        default='hd'
    )
    parser.add_argument('--words', help='Words used to generate the seed for HD Wallet')
    parser.add_argument('--passphrase', action='store_true', help='Passphrase used to generate the seed for HD Wallet')
    parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
    parser.add_argument('--prometheus', action='store_true', help='Send metric data to Prometheus')
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

    # start subprocess to handle p2p
    newpid = os.fork()
    if newpid == 0:
        # new_args should be a list like ['python', 'main-p2p.py', arg1, arg2, ...]
        new_args = [sys.executable, 'main-p2p.py']
        new_args.extend(sys.argv[1:])
        os.execv(sys.executable, new_args)

    if args.prometheus:
        kwargs = {'metrics': manager.metrics}

        if args.data:
            kwargs['path'] = os.path.join(args.data, 'prometheus')
        else:
            raise ValueError('To run prometheus exporter you must have a data path')

        prometheus = PrometheusMetricsExporter(**kwargs)
        prometheus.start()

    reactor.run()
