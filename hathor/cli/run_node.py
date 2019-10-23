import getpass
import json
import os
import sys
from argparse import ArgumentParser, Namespace
from threading import current_thread
from typing import Any, Dict

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
    namespace = u'{namespace}#{thread_name}'.format(
        namespace=event.get('log_namespace', u'-'),
        thread_name=current_thread().name,
    )
    event['log_namespace'] = namespace
    return formatEventAsClassicLogText(event)


class RunNode:
    def create_parser(self) -> ArgumentParser:
        from hathor.cli.util import create_parser
        parser = create_parser()

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
        parser.add_argument('--stratum', type=int, help='Port to run stratum server')
        parser.add_argument('--data', help='Data directory')
        parser.add_argument('--tx-storage', help='Type of storage to be used', default='compact')
        parser.add_argument('--wallet', help='Set wallet type. Options are hd (Hierarchical Deterministic) or keypair',
                            default=None)
        parser.add_argument('--wallet-enable-api', action='store_true',
                            help='Enable wallet API. Must be used with --wallet.'),
        parser.add_argument('--words', help='Words used to generate the seed for HD Wallet')
        parser.add_argument('--passphrase', action='store_true',
                            help='Passphrase used to generate the seed for HD Wallet')
        parser.add_argument('--unlock-wallet', action='store_true', help='Ask for password to unlock wallet')
        parser.add_argument('--wallet-index', action='store_true',
                            help='Create an index of transactions by address and allow searching queries')
        parser.add_argument('--prometheus', action='store_true', help='Send metric data to Prometheus')
        parser.add_argument('--cache', action='store_true', help='Use cache for tx storage')
        parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
        parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
        parser.add_argument('--recursion-limit', type=int, help='Set python recursion limit')
        parser.add_argument('--allow-mining-without-peers', action='store_true', help='Allow mining without peers')
        parser.add_argument('--min-block-weight', type=int, help='Minimum weight for blocks')
        return parser

    def prepare(self, args: Namespace) -> None:
        import hathor
        from hathor.conf import HathorSettings
        from hathor.manager import HathorManager, TestMode
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
        from hathor.p2p.peer_id import PeerId
        from hathor.p2p.utils import discover_hostname
        from hathor.transaction import genesis
        from hathor.transaction.storage import (
            TransactionStorage,
            TransactionBinaryStorage,
            TransactionCacheStorage,
            TransactionCompactStorage,
            TransactionMemoryStorage,
        )
        from hathor.wallet import HDWallet, Wallet

        settings = HathorSettings()

        loglevel_filter = LogLevelFilterPredicate(LogLevel.info)
        loglevel_filter.setLogLevelForNamespace('hathor.websocket.protocol.HathorAdminWebsocketProtocol',
                                                LogLevel.warn)
        loglevel_filter.setLogLevelForNamespace('twisted.python.log', LogLevel.warn)
        observer = FilteringLogObserver(
            FileLogObserver(sys.stdout, formatLogEvent),
            [loglevel_filter],
        )
        globalLogPublisher.addObserver(observer)

        if args.recursion_limit:
            sys.setrecursionlimit(args.recursion_limit)

        if not args.peer:
            peer_id = PeerId()
        else:
            data = json.load(open(args.peer, 'r'))
            peer_id = PeerId.create_from_json(data)

        print('Hathor v{} (genesis {})'.format(hathor.__version__, genesis.GENESIS_HASH.hex()[:7]))
        print('My peer id is', peer_id.id)

        def create_wallet():
            if args.wallet == 'hd':
                print('Using HDWallet')
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
                print('Using KeyPairWallet')
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

        tx_storage: TransactionStorage
        if args.data:
            wallet_dir = args.data
            print('Using Wallet at {}'.format(wallet_dir))
            if args.tx_storage == 'rocksdb':
                from hathor.transaction.storage import TransactionRocksDBStorage
                tx_dir = os.path.join(args.data, 'tx.db')
                tx_storage = TransactionRocksDBStorage(path=tx_dir, with_index=(not args.cache))
            else:
                tx_dir = os.path.join(args.data, 'tx')
                if args.tx_storage == 'compact':
                    tx_storage = TransactionCompactStorage(path=tx_dir, with_index=(not args.cache))
                elif args.tx_storage == 'binary':
                    tx_storage = TransactionBinaryStorage(path=tx_dir, with_index=(not args.cache))
            print('Using {} at {}'.format(tx_storage.__class__.__name__, tx_dir))
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
        self.tx_storage = tx_storage

        if args.wallet:
            self.wallet = create_wallet()
        else:
            self.wallet = None

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

        network = settings.NETWORK_NAME
        self.manager = HathorManager(reactor, peer_id=peer_id, network=network, hostname=hostname,
                                     tx_storage=self.tx_storage, wallet=self.wallet, wallet_index=args.wallet_index,
                                     stratum_port=args.stratum, min_block_weight=args.min_block_weight)
        if args.allow_mining_without_peers:
            self.manager.allow_mining_without_peers()

        dns_hosts = []
        if settings.BOOTSTRAP_DNS:
            dns_hosts.extend(settings.BOOTSTRAP_DNS)

        if args.dns:
            dns_hosts.extend(args.dns)

        if dns_hosts:
            self.manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

        if args.bootstrap:
            self.manager.add_peer_discovery(BootstrapPeerDiscovery(args.bootstrap))

        if args.test_mode_tx_weight:
            self.manager.test_mode = TestMode.TEST_TX_WEIGHT
            if self.wallet:
                self.wallet.test_mode = True

        self.start_manager()
        self.register_resources(args)

    def start_manager(self) -> None:
        self.manager.start()

    def register_resources(self, args: Namespace) -> None:
        from hathor.conf import HathorSettings
        from hathor.p2p.resources import AddPeersResource, MiningResource, StatusResource
        from hathor.prometheus import PrometheusMetricsExporter
        from hathor.resources import ProfilerResource
        from hathor.transaction.resources import (
            DashboardTransactionResource,
            DecodeTxResource,
            GraphvizLegacyResource,
            GraphvizFullResource,
            GraphvizNeighboursResource,
            PushTxResource,
            TipsHistogramResource,
            TipsResource,
            TransactionAccWeightResource,
            TransactionResource,
        )
        from hathor.version_resource import VersionResource
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
        from hathor.wallet.resources.thin_wallet import (AddressHistoryResource, SendTokensResource as
                                                         SendTokensThinResource, TokenHistoryResource, TokenResource)
        from hathor.wallet.resources.nano_contracts import (
            NanoContractDecodeResource,
            NanoContractExecuteResource,
            NanoContractMatchValueResource,
        )
        from hathor.websocket import HathorAdminWebsocketFactory, WebsocketStatsResource
        from hathor.stratum.resources import MiningStatsResource

        settings = HathorSettings()

        if args.listen:
            for description in args.listen:
                ssl = False
                if args.ssl:
                    ssl = True
                self.manager.listen(description, ssl=ssl)

        if args.prometheus:
            kwargs: Dict[str, Any] = {'metrics': self.manager.metrics}

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
            thin_wallet_resource = Resource()
            root.putChild(b'thin_wallet', thin_wallet_resource)
            contracts_resource = Resource()
            wallet_resource.putChild(b'nano-contract', contracts_resource)
            p2p_resource = Resource()
            root.putChild(b'p2p', p2p_resource)
            graphviz = GraphvizLegacyResource(self.manager)
            # XXX: reach the resource through /graphviz/ too, previously it was a leaf so this wasn't a problem
            graphviz.putChild(b'', graphviz)
            for fmt in ['dot', 'pdf', 'png', 'jpg']:
                bfmt = fmt.encode('ascii')
                graphviz.putChild(b'full.' + bfmt, GraphvizFullResource(self.manager, format=fmt))
                graphviz.putChild(b'neighbours.' + bfmt, GraphvizNeighboursResource(self.manager, format=fmt))

            resources = (
                (b'status', StatusResource(self.manager), root),
                (b'version', VersionResource(self.manager), root),
                (b'mining', MiningResource(self.manager), root),
                (b'decode_tx', DecodeTxResource(self.manager), root),
                (b'push_tx', PushTxResource(self.manager), root),
                (b'graphviz', graphviz, root),
                (b'tips-histogram', TipsHistogramResource(self.manager), root),
                (b'tips', TipsResource(self.manager), root),
                (b'transaction', TransactionResource(self.manager), root),
                (b'transaction_acc_weight', TransactionAccWeightResource(self.manager), root),
                (b'dashboard_tx', DashboardTransactionResource(self.manager), root),
                (b'profiler', ProfilerResource(self.manager), root),
                # /thin_wallet
                (b'address_history', AddressHistoryResource(self.manager), thin_wallet_resource),
                (b'send_tokens', SendTokensThinResource(self.manager), thin_wallet_resource),
                (b'token', TokenResource(self.manager), thin_wallet_resource),
                (b'token_history', TokenHistoryResource(self.manager), thin_wallet_resource),
                # /wallet/nano-contract
                (b'match-value', NanoContractMatchValueResource(self.manager), contracts_resource),
                (b'decode', NanoContractDecodeResource(self.manager), contracts_resource),
                (b'execute', NanoContractExecuteResource(self.manager), contracts_resource),
                # /p2p
                (b'peers', AddPeersResource(self.manager), p2p_resource),
            )
            for url_path, resource, parent in resources:
                parent.putChild(url_path, resource)

            if self.manager.stratum_factory is not None:
                root.putChild(b'miners', MiningStatsResource(self.manager))

            if self.wallet and args.wallet_enable_api:
                wallet_resources = (
                    # /wallet
                    (b'balance', BalanceResource(self.manager), wallet_resource),
                    (b'history', HistoryResource(self.manager), wallet_resource),
                    (b'address', AddressResource(self.manager), wallet_resource),
                    (b'send_tokens', SendTokensResource(self.manager), wallet_resource),
                    (b'sign_tx', SignTxResource(self.manager), wallet_resource),
                    (b'unlock', UnlockWalletResource(self.manager), wallet_resource),
                    (b'lock', LockWalletResource(self.manager), wallet_resource),
                    (b'state', StateWalletResource(self.manager), wallet_resource),
                )
                for url_path, resource, parent in wallet_resources:
                    parent.putChild(url_path, resource)

            # Websocket resource
            ws_factory = HathorAdminWebsocketFactory(metrics=self.manager.metrics,
                                                     wallet_index=self.manager.tx_storage.wallet_index)
            ws_factory.start()
            resource = WebSocketResource(ws_factory)
            root.putChild(b"ws", resource)

            ws_factory.subscribe(self.manager.pubsub)

            # Websocket stats resource
            root.putChild(b'websocket_stats', WebsocketStatsResource(ws_factory))

            real_root = Resource()
            real_root.putChild(settings.API_VERSION_PREFIX.encode('ascii'), root)
            status_server = server.Site(real_root)
            reactor.listenTCP(args.status, status_server)

            # Set websocket factory in metrics
            self.manager.metrics.websocket_factory = ws_factory

    def __init__(self, *, argv=None):
        if argv is None:
            import sys
            argv = sys.argv[1:]
        self.parser = self.create_parser()
        args = self.parse_args(argv)
        if args.testnet:
            if not os.environ.get('HATHOR_CONFIG_FILE'):
                os.environ['HATHOR_CONFIG_FILE'] = 'hathor.conf.testnet'
        self.prepare(args)

    def parse_args(self, argv) -> Namespace:
        return self.parser.parse_args(argv)

    def run(self) -> None:
        reactor.run()


def main():
    RunNode().run()
