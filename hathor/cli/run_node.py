# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import getpass
import json
import os
import platform
import sys
from argparse import ArgumentParser, Namespace
from typing import Any, Dict, List

from autobahn.twisted.resource import WebSocketResource
from structlog import get_logger
from twisted.internet import reactor
from twisted.web.resource import Resource

logger = get_logger()
# LOGGING_CAPTURE_STDOUT = True


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
        parser.add_argument('--listen', action='append', default=[],
                            help='Address to listen for new connections (eg: tcp:8000)')
        parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
        parser.add_argument('--status', type=int, help='Port to run status server')
        parser.add_argument('--stratum', type=int, help='Port to run stratum server')
        parser.add_argument('--data', help='Data directory')
        storage = parser.add_mutually_exclusive_group()
        storage.add_argument('--rocksdb-storage', action='store_true', help='Use RocksDB storage backend (default)')
        storage.add_argument('--old-rocksdb-storage', action='store_true',
                             help='Use old RocksDB storage backend (deprecated)')
        storage.add_argument('--memory-storage', action='store_true', help='Do not use any storage')
        storage.add_argument('--json-storage', action='store_true', help='Use legacy JSON storage (not recommended)')
        parser.add_argument('--rocksdb-cache', type=int, help='RocksDB block-table cache size (bytes)', default=None)
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
        parser.add_argument('--x-fast-init-beta', action='store_true',
                            help='Execute a fast initialization, which skips some transaction verifications. '
                            'This is still a beta feature as it may cause issues when restarting the full node '
                            'after a crash.')
        parser.add_argument('--procname-prefix', help='Add a prefix to the process name', default='')
        parser.add_argument('--allow-non-standard-script', action='store_true', help='Accept non-standard scripts on '
                            '/push-tx API')
        parser.add_argument('--max-output-script-size', type=int, default=None, help='Custom max accepted script size '
                            'on /push-tx API')
        parser.add_argument('--sentry-dsn', help='Sentry DSN')
        return parser

    def prepare(self, args: Namespace) -> None:
        import hathor
        from hathor.cli.util import check_or_exit
        from hathor.conf import HathorSettings
        from hathor.daa import TestMode, _set_test_mode
        from hathor.manager import HathorManager
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
        from hathor.p2p.peer_id import PeerId
        from hathor.p2p.utils import discover_hostname
        from hathor.transaction import genesis
        from hathor.transaction.storage import (
            TransactionCacheStorage,
            TransactionCompactStorage,
            TransactionMemoryStorage,
            TransactionOldRocksDBStorage,
            TransactionRocksDBStorage,
            TransactionStorage,
        )
        from hathor.wallet import HDWallet, Wallet

        settings = HathorSettings()
        self.log = logger.new()

        from setproctitle import setproctitle
        setproctitle('{}hathor-core'.format(args.procname_prefix))

        if args.recursion_limit:
            sys.setrecursionlimit(args.recursion_limit)
        else:
            sys.setrecursionlimit(5000)

        try:
            import resource
        except ModuleNotFoundError:
            pass
        else:
            (nofile_soft, _) = resource.getrlimit(resource.RLIMIT_NOFILE)
            if nofile_soft < 256:
                print('Maximum number of open file descriptors is too low. Minimum required is 256.')
                sys.exit(-2)

        if not args.peer:
            peer_id = PeerId()
        else:
            data = json.load(open(args.peer, 'r'))
            peer_id = PeerId.create_from_json(data)

        python = f'{platform.python_version()}-{platform.python_implementation()}'

        self.log.info(
            'hathor-core v{hathor}',
            hathor=hathor.__version__,
            pid=os.getpid(),
            genesis=genesis.GENESIS_HASH.hex()[:7],
            my_peer_id=str(peer_id.id),
            python=python,
            platform=platform.platform()
        )

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
        if args.memory_storage:
            check_or_exit(not args.data, '--data should not be used with --memory-storage')
            # if using MemoryStorage, no need to have cache
            tx_storage = TransactionMemoryStorage()
            self.log.info('with storage', storage_class=type(tx_storage).__name__)
        elif args.json_storage:
            check_or_exit(args.data, '--data is expected')
            tx_storage = TransactionCompactStorage(path=args.data, with_index=(not args.cache))
        elif args.old_rocksdb_storage:
            check_or_exit(args.data, '--data is expected')
            self.log.warn('the old rocksdb storage is deprecated and support will be removed')
            tx_storage = TransactionOldRocksDBStorage(path=args.data)
        else:
            check_or_exit(args.data, '--data is expected')
            if args.rocksdb_storage:
                self.log.warn('--rocksdb-storage is now implied, no need to specify it')
            cache_capacity = args.rocksdb_cache
            tx_storage = TransactionRocksDBStorage(path=args.data, with_index=(not args.cache),
                                                   cache_capacity=cache_capacity)
        self.log.info('with storage', storage_class=type(tx_storage).__name__, path=args.data)
        if args.cache:
            check_or_exit(not args.memory_storage, '--cache should not be used with --memory-storage')
            tx_storage = TransactionCacheStorage(tx_storage, reactor)
            if args.cache_size:
                tx_storage.capacity = args.cache_size
            if args.cache_interval:
                tx_storage.interval = args.cache_interval
            self.log.info('with cache', capacity=tx_storage.capacity, interval=tx_storage.interval)
        self.tx_storage = tx_storage

        if args.wallet:
            self.wallet = create_wallet()
            self.log.info('with wallet', wallet=self.wallet, path=args.data)
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
                                     stratum_port=args.stratum, ssl=True, checkpoints=settings.CHECKPOINTS)
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
            _set_test_mode(TestMode.TEST_TX_WEIGHT)
            if self.wallet:
                self.wallet.test_mode = True

        if not args.x_fast_init_beta:
            self.manager._full_verification = True

        for description in args.listen:
            self.manager.add_listen_address(description)

        self.start_manager(args)
        self.register_resources(args)

    def start_sentry_if_possible(self, args: Namespace) -> None:
        """Start Sentry integration if possible."""
        if not args.sentry_dsn:
            return
        self.log.info('Starting Sentry', dsn=args.sentry_dsn)
        try:
            import sentry_sdk
            from structlog_sentry import SentryProcessor  # noqa: F401
        except ModuleNotFoundError:
            self.log.error('Please use `poetry install -E sentry` for enabling Sentry.')
            sys.exit(-3)

        import hathor
        from hathor.conf import HathorSettings
        settings = HathorSettings()
        sentry_sdk.init(
            dsn=args.sentry_dsn,
            release=hathor.__version__,
            environment=settings.NETWORK_NAME,
        )

    def start_manager(self, args: Namespace) -> None:
        self.start_sentry_if_possible(args)
        self.manager.start()

    def register_resources(self, args: Namespace) -> None:
        from hathor.conf import HathorSettings
        from hathor.mining.ws import MiningWebsocketFactory
        from hathor.p2p.resources import AddPeersResource, MiningInfoResource, MiningResource, StatusResource
        from hathor.profiler import get_cpu_profiler
        from hathor.profiler.resources import CPUProfilerResource, ProfilerResource
        from hathor.prometheus import PrometheusMetricsExporter
        from hathor.transaction.resources import (
            BlockAtHeightResource,
            CreateTxResource,
            DashboardTransactionResource,
            DecodeTxResource,
            GetBlockTemplateResource,
            GraphvizFullResource,
            GraphvizNeighboursResource,
            MempoolResource,
            PushTxResource,
            SubmitBlockResource,
            TransactionAccWeightResource,
            TransactionResource,
            TxParentsResource,
            ValidateAddressResource,
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
        from hathor.wallet.resources.nano_contracts import (
            NanoContractDecodeResource,
            NanoContractExecuteResource,
            NanoContractMatchValueResource,
        )
        from hathor.wallet.resources.thin_wallet import (
            AddressBalanceResource,
            AddressHistoryResource,
            AddressSearchResource,
            SendTokensResource as SendTokensThinResource,
            TokenHistoryResource,
            TokenResource,
        )
        from hathor.websocket import HathorAdminWebsocketFactory, WebsocketStatsResource

        settings = HathorSettings()
        cpu = get_cpu_profiler()

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
            graphviz = Resource()
            # XXX: reach the resource through /graphviz/ too, previously it was a leaf so this wasn't a problem
            graphviz.putChild(b'', graphviz)
            for fmt in ['dot', 'pdf', 'png', 'jpg']:
                bfmt = fmt.encode('ascii')
                graphviz.putChild(b'full.' + bfmt, GraphvizFullResource(self.manager, format=fmt))
                graphviz.putChild(b'neighbours.' + bfmt, GraphvizNeighboursResource(self.manager, format=fmt))

            resources = (
                (b'status', StatusResource(self.manager), root),
                (b'version', VersionResource(self.manager), root),
                (b'create_tx', CreateTxResource(self.manager), root),
                (b'decode_tx', DecodeTxResource(self.manager), root),
                (b'validate_address', ValidateAddressResource(self.manager), root),
                (b'push_tx',
                    PushTxResource(self.manager, args.max_output_script_size, args.allow_non_standard_script),
                    root),
                (b'graphviz', graphviz, root),
                (b'transaction', TransactionResource(self.manager), root),
                (b'block_at_height', BlockAtHeightResource(self.manager), root),
                (b'transaction_acc_weight', TransactionAccWeightResource(self.manager), root),
                (b'dashboard_tx', DashboardTransactionResource(self.manager), root),
                (b'profiler', ProfilerResource(self.manager), root),
                (b'top', CPUProfilerResource(self.manager, cpu), root),
                (b'mempool', MempoolResource(self.manager), root),
                # mining
                (b'mining', MiningResource(self.manager), root),
                (b'getmininginfo', MiningInfoResource(self.manager), root),
                (b'get_block_template', GetBlockTemplateResource(self.manager), root),
                (b'submit_block', SubmitBlockResource(self.manager), root),
                (b'tx_parents', TxParentsResource(self.manager), root),
                # /thin_wallet
                (b'address_history', AddressHistoryResource(self.manager), thin_wallet_resource),
                (b'address_balance', AddressBalanceResource(self.manager), thin_wallet_resource),
                (b'address_search', AddressSearchResource(self.manager), thin_wallet_resource),
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
                from hathor.stratum.resources import MiningStatsResource
                root.putChild(b'miners', MiningStatsResource(self.manager))

            with_wallet_api = bool(self.wallet and args.wallet_enable_api)
            if with_wallet_api:
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
            root.putChild(b'ws', WebSocketResource(ws_factory))

            # Mining websocket resource
            mining_ws_factory = MiningWebsocketFactory(self.manager)
            root.putChild(b'mining_ws', WebSocketResource(mining_ws_factory))

            ws_factory.subscribe(self.manager.pubsub)

            # Websocket stats resource
            root.putChild(b'websocket_stats', WebsocketStatsResource(ws_factory))

            real_root = Resource()
            real_root.putChild(settings.API_VERSION_PREFIX.encode('ascii'), root)

            from hathor.profiler.site import SiteProfiler
            status_server = SiteProfiler(real_root)
            reactor.listenTCP(args.status, status_server)
            self.log.info('with status', listen=args.status, with_wallet_api=with_wallet_api)

            # Set websocket factory in metrics
            self.manager.metrics.websocket_factory = ws_factory

    def register_signal_handlers(self, args: Namespace) -> None:
        """Register signal handlers."""
        import signal
        sigusr1 = getattr(signal, 'SIGUSR1', None)
        if sigusr1 is not None:
            # USR1 is avaiable in this OS.
            signal.signal(sigusr1, self.signal_usr1_handler)

    def signal_usr1_handler(self, sig: int, frame: Any) -> None:
        """Called when USR1 signal is received."""
        self.log.warn('USR1 received. Killing all connections...')
        if self.manager and self.manager.connections:
            self.manager.connections.disconnect_all_peers(force=True)

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
        self.register_signal_handlers(args)

    def parse_args(self, argv: List[str]) -> Namespace:
        return self.parser.parse_args(argv)

    def run(self) -> None:
        reactor.run()


def main():
    RunNode().run()
