from twisted.internet import reactor
from twisted.logger import FileLogObserver, formatEventAsClassicLogText
from twisted.logger import globalLogPublisher, FilteringLogObserver, LogLevelFilterPredicate, LogLevel

from hathor.p2p.peer_id import PeerId
from hathor.manager import HathorManager
from hathor.transaction.storage import TransactionCompactStorage, TransactionMemoryStorage, TransactionCacheStorage
from hathor.wallet import Wallet, HDWallet
from hathor.p2p.peer_discovery import DNSPeerDiscovery, BootstrapPeerDiscovery
import hathor

import argparse
import getpass
import sys
import json
import os


def formatLogEvent(event):
    return formatEventAsClassicLogText(event)


def get_ipython(extra_args, imported_objects):
    from IPython import start_ipython

    def run_ipython():
        start_ipython(argv=extra_args, user_ns=imported_objects)

    return run_ipython


def create_parser():
    # TODO: reuse as much as possible from hathor.cli.run_node
    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor testnet')
    parser.add_argument('--dns', action='append', help='Seed DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
    parser.add_argument('--data', help='Data directory')
    parser.add_argument(
        '--wallet',
        help='Set wallet type. Options are hd (Hierarchical Deterministic) or keypair',
        default='hd'
    )
    parser.add_argument('--words', help='Words used to generate the seed for HD Wallet')
    parser.add_argument('--passphrase', action='store_true', help='Passphrase used to generate the seed for HD Wallet')
    parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
    parser.add_argument('--cache', action='store_true', help='Use cache for tx storage')
    parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
    parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
    return parser


def prepare(args, extra_args=[]):
    loglevel_filter = LogLevelFilterPredicate(LogLevel.info)
    loglevel_filter.setLogLevelForNamespace('hathor.websocket.protocol.HathorAdminWebsocketProtocol', LogLevel.warn)
    loglevel_filter.setLogLevelForNamespace('twisted.python.log', LogLevel.warn)
    observer = FilteringLogObserver(
        FileLogObserver(sys.stdout, formatLogEvent),
        [loglevel_filter],
    )
    globalLogPublisher.addObserver(observer)

    if not args.peer:
        peer_id = PeerId()
    else:
        data = json.load(open(args.peer, 'r'))
        peer_id = PeerId.create_from_json(data)

    print('Hathor v{}'.format(hathor.__version__))
    print('My peer id is', peer_id.id)

    imported_objects = {}

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
        print('Using Wallet at {}'.format(wallet_dir))
        print('Using TransactionCompactStorage at {}'.format(tx_dir))
        tx_storage = TransactionCompactStorage(path=tx_dir, with_index=(not args.cache))
        if args.cache:
            tx_storage = TransactionCacheStorage(tx_storage, reactor)
            if args.cache_size:
                tx_storage.capacity = args.cache_size
            if args.cache_interval:
                tx_storage.interval = args.cache_interval
            print('Using TransactionCacheStorage, capacity {}, interval {}s'
                  .format(tx_storage.capacity, tx_storage.interval))
            # tx_storage.start()
    else:
        # if using MemoryStorage, no need to have cache
        tx_storage = TransactionMemoryStorage()
        print('Using TransactionMemoryStorage')
    imported_objects['tx_storage'] = tx_storage

    wallet = create_wallet()
    imported_objects['wallet'] = wallet

    network = 'testnet'
    manager = HathorManager(reactor, peer_id=peer_id, network=network,
                            hostname=args.hostname, tx_storage=tx_storage, wallet=wallet)
    imported_objects['manager'] = manager

    dns_hosts = []
    if args.testnet:
        dns_hosts.append('testnet.hathor.network')

    if args.dns:
        dns_hosts.extend(dns_hosts)

    if dns_hosts:
        manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

    if args.bootstrap:
        manager.add_peer_discovery(BootstrapPeerDiscovery(args.bootstrap))

    print()
    print('--- Injected globals ---')
    for name, obj in imported_objects.items():
        print(name, obj)
    print('------------------------')
    print()

    shell = get_ipython(extra_args, imported_objects)
    return shell


def main():
    parser = create_parser()
    # TODO: add help for the `--` extra argument separator
    extra_args = []
    argv = sys.argv[1:]
    if '--' in argv:
        idx = argv.index('--')
        extra_args = argv[idx + 1:]
        argv = argv[:idx]

    args = parser.parse_args(argv)
    shell = prepare(args, extra_args)
    shell()
