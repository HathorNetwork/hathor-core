import argparse
import getpass
import json
import os
import sys

from autobahn.twisted.resource import WebSocketResource
from twisted.internet import reactor
from twisted.logger import (
    FileLogObserver,
    FilteringLogObserver,
    LogLevel,
    LogLevelFilterPredicate,
    formatEventAsClassicLogText,
    globalLogPublisher,
)
from twisted.web import server
from twisted.web.resource import Resource


def formatLogEvent(event):
    return formatEventAsClassicLogText(event)


def main():
    import hathor
    from hathor.manager import HathorManager, TestMode
    from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
    from hathor.p2p.peer_id import PeerId
    from hathor.p2p.resources import MiningResource, StatusResource
    from hathor.prometheus import PrometheusMetricsExporter
    from hathor.resources import ProfilerResource
    from hathor.transaction.resources import (
        DashboardTransactionResource,
        DecodeTxResource,
        GraphvizResource,
        PushTxResource,
        TipsHistogramResource,
        TipsResource,
        TransactionResource,
    )
    from hathor.p2p.utils import discover_hostname
    from hathor.transaction.storage import TransactionCacheStorage, TransactionCompactStorage, TransactionMemoryStorage
    from hathor.version_resource import VersionResource
    from hathor.wallet import HDWallet, Wallet
    from hathor.wallet.resources import (
        AddressResource,
        BalanceResource,
        HistoryResource,
        LockWalletResource,
        SendTokensResource,
        SignTxResource,
        StateWalletResource,
        UnlockWalletResource,
    )
    from hathor.wallet.resources.nano_contracts import (
        NanoContractDecodeResource,
        NanoContractExecuteResource,
        NanoContractMatchValueResource,
    )
    from hathor.websocket import HathorAdminWebsocketFactory

    parser = argparse.ArgumentParser()
    parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
    parser.add_argument('--auto-hostname', action='store_true', help='Try to discover the hostname automatically')
    parser.add_argument('--testnet', action='store_true', help='Connect to Hathor testnet')
    parser.add_argument('--test-mode-tx-weight', action='store_true',
                        help='Reduces tx weight to 1 for testing purposes')
    parser.add_argument('--dns', action='append', help='Seed DNS')
    parser.add_argument('--peer', help='json file with peer info')
    parser.add_argument('--listen', action='append', help='Address to listen for new connections (eg: tcp:8000)')
    parser.add_argument('--ssl', action='store_true', help='Listen to ssl connection')
    parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
    parser.add_argument('--status', type=int, help='Port to run status server')
    parser.add_argument('--data', help='Data directory')
    parser.add_argument('--wallet', help='Set wallet type. Options are hd (Hierarchical Deterministic) or keypair',
                        default='hd')
    parser.add_argument('--words', help='Words used to generate the seed for HD Wallet')
    parser.add_argument('--passphrase', action='store_true', help='Passphrase used to generate the seed for HD Wallet')
    parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
    parser.add_argument('--prometheus', action='store_true', help='Send metric data to Prometheus')
    parser.add_argument('--cache', action='store_true', help='Use cache for tx storage')
    parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
    parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
    args = parser.parse_args()

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
            print('Using TransactionCacheStorage, capacity {}, interval {}s'.format(
                tx_storage.capacity, tx_storage.interval))
            tx_storage.start()
    else:
        # if using MemoryStorage, no need to have cache
        tx_storage = TransactionMemoryStorage()
        print('Using TransactionMemoryStorage')

    wallet = create_wallet()

    if args.hostname and args.auto_hostname:
        print('You cannot use --hostname and --auto-hostname together.')
        sys.exit(-1)

    if not args.auto_hostname:
        hostname = args.hostname
    else:
        print('Trying to discover your hostname...')
        hostname = discover_hostname()
        if not hostname:
            print('Aborting because we could not discover your hostname.')
            print('Try again or run without --auto-hostname.')
            sys.exit(-1)
        print('Hostname discovered and set to {}'.format(hostname))

    network = 'testnet'
    manager = HathorManager(reactor, peer_id=peer_id, network=network, hostname=hostname, tx_storage=tx_storage,
                            wallet=wallet)

    dns_hosts = []
    if args.testnet:
        dns_hosts.append('testnet.hathor.network')

    if args.dns:
        dns_hosts.extend(dns_hosts)

    if dns_hosts:
        manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

    if args.bootstrap:
        manager.add_peer_discovery(BootstrapPeerDiscovery(args.bootstrap))

    if args.test_mode_tx_weight:
        manager.test_mode = TestMode.TEST_TX_WEIGHT

    manager.start()

    if args.listen:
        for description in args.listen:
            ssl = False
            if args.ssl:
                ssl = True
            manager.listen(description, ssl=ssl)

    if args.prometheus:
        kwargs = {'metrics': manager.metrics}

        if args.data:
            kwargs['path'] = os.path.join(args.data, 'prometheus')
        else:
            raise ValueError('To run prometheus exporter you must have a data path')

        prometheus = PrometheusMetricsExporter(**kwargs)
        prometheus.start()

    if args.status:
        # TODO get this from a file. How should we do with the factory?
        root = Resource()
        wallet_resource = Resource()
        root.putChild(b'wallet', wallet_resource)
        contracts_resource = Resource()
        wallet_resource.putChild(b'nano-contract', contracts_resource)

        resources = (
            (b'status', StatusResource(manager), root),
            (b'version', VersionResource(), root),
            (b'mining', MiningResource(manager), root),
            (b'decode_tx', DecodeTxResource(manager), root),
            (b'push_tx', PushTxResource(manager), root),
            (b'graphviz', GraphvizResource(manager), root),
            (b'tips-histogram', TipsHistogramResource(manager), root),
            (b'tips', TipsResource(manager), root),
            (b'transaction', TransactionResource(manager), root),
            (b'dashboard_tx', DashboardTransactionResource(manager), root),
            (b'profiler', ProfilerResource(manager), root),
            # /wallet
            (b'balance', BalanceResource(manager), wallet_resource),
            (b'history', HistoryResource(manager), wallet_resource),
            (b'address', AddressResource(manager), wallet_resource),
            (b'send_tokens', SendTokensResource(manager), wallet_resource),
            (b'sign_tx', SignTxResource(manager), wallet_resource),
            (b'unlock', UnlockWalletResource(manager), wallet_resource),
            (b'lock', LockWalletResource(manager), wallet_resource),
            (b'state', StateWalletResource(manager), wallet_resource),
            # /wallet/nano-contract
            (b'match-value', NanoContractMatchValueResource(manager), contracts_resource),
            (b'decode', NanoContractDecodeResource(manager), contracts_resource),
            (b'execute', NanoContractExecuteResource(manager), contracts_resource),
        )
        for url_path, resource, parent in resources:
            parent.putChild(url_path, resource)

        # Websocket resource
        ws_factory = HathorAdminWebsocketFactory(metrics=manager.metrics)
        ws_factory.start()
        resource = WebSocketResource(ws_factory)
        root.putChild(b"ws", resource)

        ws_factory.subscribe(manager.pubsub)

        status_server = server.Site(root)
        reactor.listenTCP(args.status, status_server)

    reactor.run()
