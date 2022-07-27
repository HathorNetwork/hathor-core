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
from typing import Any, Callable, Dict, List, Tuple

from autobahn.twisted.resource import WebSocketResource
from structlog import get_logger
from twisted.web.resource import Resource

logger = get_logger()
# LOGGING_CAPTURE_STDOUT = True


class RunNode:
    UNSAFE_ARGUMENTS: List[Tuple[str, Callable[[Namespace], bool]]] = [
        ('--test-mode-tx-weight', lambda args: bool(args.test_mode_tx_weight)),
        ('--enable-crash-api', lambda args: bool(args.enable_crash_api)),
        ('--x-sync-bridge', lambda args: bool(args.x_sync_bridge)),
        ('--x-sync-v2-only', lambda args: bool(args.x_sync_v2_only)),
    ]

    def create_parser(self) -> ArgumentParser:
        from hathor.cli.util import create_parser
        parser = create_parser()

        parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
        parser.add_argument('--auto-hostname', action='store_true', help='Try to discover the hostname automatically')
        parser.add_argument('--unsafe-mode',
                            help='Enable unsafe parameters. **NEVER USE IT IN PRODUCTION ENVIRONMENT**')
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
        parser.add_argument('--utxo-index', action='store_true',
                            help='Create an index of UTXOs by token/address/amount and allow searching queries')
        parser.add_argument('--prometheus', action='store_true', help='Send metric data to Prometheus')
        parser.add_argument('--cache', action='store_true', help='Use cache for tx storage')
        parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
        parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
        parser.add_argument('--recursion-limit', type=int, help='Set python recursion limit')
        parser.add_argument('--allow-mining-without-peers', action='store_true', help='Allow mining without peers')
        fvargs = parser.add_mutually_exclusive_group()
        fvargs.add_argument('--x-full-verification', action='store_true', help='Fully validate the local database')
        fvargs.add_argument('--x-fast-init-beta', action='store_true',
                            help='Execute a fast initialization, which skips some transaction verifications. '
                            'This is still a beta feature as it may cause issues when restarting the full node '
                            'after a crash.')
        parser.add_argument('--procname-prefix', help='Add a prefix to the process name', default='')
        parser.add_argument('--allow-non-standard-script', action='store_true', help='Accept non-standard scripts on '
                            '/push-tx API')
        parser.add_argument('--max-output-script-size', type=int, default=None, help='Custom max accepted script size '
                            'on /push-tx API')
        parser.add_argument('--sentry-dsn', help='Sentry DSN')
        parser.add_argument('--enable-debug-api', action='store_true', help='Enable _debug/* endpoints')
        parser.add_argument('--enable-crash-api', action='store_true', help='Enable _crash/* endpoints')
        v2args = parser.add_mutually_exclusive_group()
        v2args.add_argument('--x-sync-bridge', action='store_true',
                            help='Enable support for running both sync protocols. DO NOT ENABLE, IT WILL BREAK.')
        v2args.add_argument('--x-sync-v2-only', action='store_true',
                            help='Disable support for running sync-v1. DO NOT ENABLE, IT WILL BREAK.')
        parser.add_argument('--x-localhost-only', action='store_true', help='Only connect to peers on localhost')
        parser.add_argument('--x-rocksdb-indexes', action='store_true', help='Use RocksDB indexes (currently opt-in)')
        return parser

    def prepare(self, args: Namespace) -> None:
        import hathor
        from hathor.cli.util import check_or_exit
        from hathor.conf import HathorSettings
        from hathor.conf.get_settings import get_settings_module
        from hathor.daa import TestMode, _set_test_mode
        from hathor.manager import HathorManager
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
        from hathor.p2p.peer_id import PeerId
        from hathor.p2p.utils import discover_hostname
        from hathor.storage import RocksDBStorage
        from hathor.transaction import genesis
        from hathor.transaction.storage import (
            TransactionCacheStorage,
            TransactionCompactStorage,
            TransactionMemoryStorage,
            TransactionRocksDBStorage,
            TransactionStorage,
        )
        from hathor.util import reactor
        from hathor.wallet import HDWallet, Wallet

        settings = HathorSettings()
        settings_module = get_settings_module()  # only used for logging its location
        self.log = logger.new()
        self.reactor = reactor

        from setproctitle import setproctitle
        setproctitle('{}hathor-core'.format(args.procname_prefix))

        if args.recursion_limit:
            sys.setrecursionlimit(args.recursion_limit)
        else:
            sys.setrecursionlimit(5000)

        if sys.platform != 'win32':
            import resource
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

        self.check_unsafe_arguments(args)

        self.log.info(
            'hathor-core v{hathor}',
            hathor=hathor.__version__,
            pid=os.getpid(),
            genesis=genesis.GENESIS_HASH.hex()[:7],
            my_peer_id=str(peer_id.id),
            python=python,
            platform=platform.platform(),
            settings=settings_module.__file__,
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
        rocksdb_storage: RocksDBStorage
        if args.memory_storage:
            check_or_exit(not args.data, '--data should not be used with --memory-storage')
            # if using MemoryStorage, no need to have cache
            tx_storage = TransactionMemoryStorage()
            assert not args.x_rocksdb_indexes, 'RocksDB indexes require RocksDB data'
            self.log.info('with storage', storage_class=type(tx_storage).__name__)
        elif args.json_storage:
            check_or_exit(args.data, '--data is expected')
            assert not args.x_rocksdb_indexes, 'RocksDB indexes require RocksDB data'
            tx_storage = TransactionCompactStorage(path=args.data, with_index=(not args.cache))
        else:
            check_or_exit(args.data, '--data is expected')
            if args.rocksdb_storage:
                self.log.warn('--rocksdb-storage is now implied, no need to specify it')
            cache_capacity = args.rocksdb_cache
            use_memory_indexes = not args.x_rocksdb_indexes
            rocksdb_storage = RocksDBStorage(path=args.data, cache_capacity=cache_capacity)
            tx_storage = TransactionRocksDBStorage(rocksdb_storage=rocksdb_storage,
                                                   with_index=(not args.cache),
                                                   use_memory_indexes=use_memory_indexes)
        self.log.info('with storage', storage_class=type(tx_storage).__name__, path=args.data)
        if args.cache:
            check_or_exit(not args.memory_storage, '--cache should not be used with --memory-storage')
            tx_storage = TransactionCacheStorage(tx_storage, self.reactor)
            if args.cache_size:
                tx_storage.capacity = args.cache_size
            if args.cache_interval:
                tx_storage.interval = args.cache_interval
            self.log.info('with cache', capacity=tx_storage.capacity, interval=tx_storage.interval)
        self.tx_storage = tx_storage
        self.log.info('with indexes', indexes_class=type(tx_storage.indexes).__name__)

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
        enable_sync_v1 = not args.x_sync_v2_only
        enable_sync_v2 = args.x_sync_v2_only or args.x_sync_bridge

        self.manager = HathorManager(
            self.reactor,
            peer_id=peer_id,
            network=network,
            hostname=hostname,
            tx_storage=self.tx_storage,
            wallet=self.wallet,
            wallet_index=args.wallet_index,
            utxo_index=args.utxo_index,
            stratum_port=args.stratum,
            ssl=True,
            checkpoints=settings.CHECKPOINTS,
            enable_sync_v1=enable_sync_v1,
            enable_sync_v2=enable_sync_v2,
            soft_voided_tx_ids=set(settings.SOFT_VOIDED_TX_IDS),
        )
        if args.allow_mining_without_peers:
            self.manager.allow_mining_without_peers()

        if args.x_localhost_only:
            self.manager.connections.localhost_only = True

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

        if args.x_full_verification:
            self.manager._full_verification = True
        if args.x_fast_init_beta:
            self.log.warn('--x-fast-init-beta is now the default, no need to specify it')

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
        from hathor.debug_resources import (
            DebugCrashResource,
            DebugLogResource,
            DebugMessAroundResource,
            DebugPrintResource,
            DebugRaiseResource,
            DebugRejectResource,
        )
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
            UtxoSearchResource,
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

            resources = [
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
            ]
            # XXX: only enable UTXO search API if the index is enabled
            if args.utxo_index:
                resources.extend([
                    (b'utxo_search', UtxoSearchResource(self.manager), root),
                ])

            if args.enable_debug_api:
                debug_resource = Resource()
                root.putChild(b'_debug', debug_resource)
                resources.extend([
                    (b'log', DebugLogResource(), debug_resource),
                    (b'raise', DebugRaiseResource(), debug_resource),
                    (b'reject', DebugRejectResource(), debug_resource),
                    (b'print', DebugPrintResource(), debug_resource),
                ])
            if args.enable_crash_api:
                crash_resource = Resource()
                root.putChild(b'_crash', crash_resource)
                resources.extend([
                    (b'exit', DebugCrashResource(), crash_resource),
                    (b'mess_around', DebugMessAroundResource(self.manager), crash_resource),
                ])

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
            assert self.manager.tx_storage.indexes is not None
            ws_factory = HathorAdminWebsocketFactory(metrics=self.manager.metrics,
                                                     address_index=self.manager.tx_storage.indexes.addresses)
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
            self.reactor.listenTCP(args.status, status_server)
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

    def check_unsafe_arguments(self, args: Namespace) -> None:
        unsafe_args_found = []
        for arg_cmdline, arg_test_fn in self.UNSAFE_ARGUMENTS:
            if arg_test_fn(args):
                unsafe_args_found.append(arg_cmdline)

        if args.unsafe_mode is None:
            if unsafe_args_found:
                message = [
                    'You need to enable --unsafe-mode to run with these arguments.',
                    '',
                    'The following argument require unsafe mode:',
                ]
                for arg_cmdline in unsafe_args_found:
                    message.append(arg_cmdline)
                message.extend([
                    '',
                    'Never enable UNSAFE MODE in a production environment.'
                ])
                self.log.critical('\n'.join(message))
                sys.exit(-1)

        else:
            fail = False
            message = [
                'UNSAFE MODE IS ENABLED',
                '',
                '********************************************************',
                '********************************************************',
                '',
                'UNSAFE MODE IS ENABLED',
                '',
                'You should never use --unsafe-mode in production environments.',
                '',
            ]

            from hathor.conf import HathorSettings
            settings = HathorSettings()

            if args.unsafe_mode != settings.NETWORK_NAME:
                message.extend([
                    f'Unsafe mode enabled for wrong network ({args.unsafe_mode} != {settings.NETWORK_NAME}).',
                    '',
                ])
                fail = True

            is_local_network = True
            if settings.NETWORK_NAME == 'mainnet':
                is_local_network = False
            elif settings.NETWORK_NAME.startswith('testnet'):
                is_local_network = False

            if not is_local_network:
                message.extend([
                    f'You should not enable unsafe mode on {settings.NETWORK_NAME} unless you know what you are doing',
                    '',
                ])

            if not unsafe_args_found:
                message.extend([
                    '--unsafe-mode is not needed because you have not enabled any unsafe feature.',
                    '',
                    'Remove --unsafe-mode and try again.',
                ])
                fail = True
            else:
                message.append('You have enabled the following features:')
                for arg_cmdline in unsafe_args_found:
                    message.append(arg_cmdline)

            message.extend([
                '',
                '********************************************************',
                '********************************************************',
                '',
            ])

            self.log.critical('\n'.join(message))
            if fail:
                sys.exit(-1)

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
        self.reactor.run()


def main():
    RunNode().run()
