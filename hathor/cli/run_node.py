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

import os
import sys
from argparse import SUPPRESS, ArgumentParser, Namespace
from typing import Any, Callable

from pydantic import ValidationError
from structlog import get_logger

from hathor.cli.run_node_args import RunNodeArgs
from hathor.conf import TESTNET_SETTINGS_FILEPATH, HathorSettings
from hathor.exception import PreInitializationError
from hathor.feature_activation.feature import Feature

logger = get_logger()
# LOGGING_CAPTURE_STDOUT = True


class RunNode:
    UNSAFE_ARGUMENTS: list[tuple[str, Callable[[RunNodeArgs], bool]]] = [
        ('--test-mode-tx-weight', lambda args: bool(args.test_mode_tx_weight)),
        ('--enable-crash-api', lambda args: bool(args.enable_crash_api)),
        ('--x-sync-bridge', lambda args: bool(args.x_sync_bridge)),
        ('--x-sync-v2-only', lambda args: bool(args.x_sync_v2_only)),
        ('--x-enable-event-queue', lambda args: bool(args.x_enable_event_queue))
    ]

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        """
        Create a new parser with the run_node CLI arguments.
        Arguments must also be added to hathor.cli.run_node_args.RunNodeArgs
        """
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
        parser.add_argument('--sysctl',
                            help='Endpoint description (eg: unix:/path/sysctl.sock, tcp:5000:interface:127.0.0.1)')
        parser.add_argument('--listen', action='append', default=[],
                            help='Address to listen for new connections (eg: tcp:8000)')
        parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
        parser.add_argument('--status', type=int, help='Port to run status server')
        parser.add_argument('--stratum', type=int, help='Port to run stratum server')
        parser.add_argument('--data', help='Data directory')
        storage = parser.add_mutually_exclusive_group()
        storage.add_argument('--rocksdb-storage', action='store_true', help='Use RocksDB storage backend (default)')
        storage.add_argument('--memory-storage', action='store_true', help='Do not use a persistent storage')
        parser.add_argument('--memory-indexes', action='store_true',
                            help='Use memory indexes when using RocksDB storage (startup is significantly slower)')
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
        parser.add_argument('--prometheus-prefix', default='',
                            help='A prefix that will be added in all Prometheus metrics')
        parser.add_argument('--cache', action='store_true', help='Use cache for tx storage')
        parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
        parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
        parser.add_argument('--recursion-limit', type=int, help='Set python recursion limit')
        parser.add_argument('--allow-mining-without-peers', action='store_true', help='Allow mining without peers')
        fvargs = parser.add_mutually_exclusive_group()
        fvargs.add_argument('--x-full-verification', action='store_true', help='Fully validate the local database')
        parser.add_argument('--procname-prefix', help='Add a prefix to the process name', default='')
        parser.add_argument('--allow-non-standard-script', action='store_true', help='Accept non-standard scripts on '
                            '/push-tx API')
        parser.add_argument('--max-output-script-size', type=int, default=None, help='Custom max accepted script size '
                            'on /push-tx API')
        parser.add_argument('--sentry-dsn', help='Sentry DSN')
        parser.add_argument('--enable-debug-api', action='store_true', help='Enable _debug/* endpoints')
        parser.add_argument('--enable-crash-api', action='store_true', help='Enable _crash/* endpoints')
        parser.add_argument('--x-enable-legacy-sync-v1_0', action='store_true', help='Enable sync-v1.0, will not '
                            'disable sync-v1.1')
        v2args = parser.add_mutually_exclusive_group()
        v2args.add_argument('--x-sync-bridge', action='store_true',
                            help='Enable support for running both sync protocols. DO NOT ENABLE, IT WILL BREAK.')
        v2args.add_argument('--x-sync-v2-only', action='store_true',
                            help='Disable support for running sync-v1. DO NOT ENABLE, IT WILL BREAK.')
        parser.add_argument('--x-localhost-only', action='store_true', help='Only connect to peers on localhost')
        parser.add_argument('--x-rocksdb-indexes', action='store_true', help=SUPPRESS)
        parser.add_argument('--x-enable-event-queue', action='store_true', help='Enable event queue mechanism')
        parser.add_argument('--peer-id-blacklist', action='extend', default=[], nargs='+', type=str,
                            help='Peer IDs to forbid connection')
        parser.add_argument('--config-yaml', type=str, help='Configuration yaml filepath')
        possible_features = [feature.value for feature in Feature]
        parser.add_argument('--signal-support', default=[], action='append', choices=possible_features,
                            help=f'Signal support for a feature. One of {possible_features}')
        parser.add_argument('--signal-not-support', default=[], action='append', choices=possible_features,
                            help=f'Signal not support for a feature. One of {possible_features}')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        from setproctitle import setproctitle
        setproctitle('{}hathor-core'.format(self._args.procname_prefix))

        if self._args.recursion_limit:
            sys.setrecursionlimit(self._args.recursion_limit)
        else:
            sys.setrecursionlimit(5000)

        if sys.platform != 'win32':
            import resource
            (nofile_soft, _) = resource.getrlimit(resource.RLIMIT_NOFILE)
            if nofile_soft < 256:
                print('Maximum number of open file descriptors is too low. Minimum required is 256.')
                sys.exit(-2)

        self.check_unsafe_arguments()
        self.check_python_version()

        from hathor.util import reactor
        self.reactor = reactor

        from hathor.builder import CliBuilder, ResourcesBuilder
        from hathor.exception import BuilderError
        builder = CliBuilder(self._args)
        try:
            self.manager = builder.create_manager(reactor)
        except BuilderError as err:
            self.log.error(str(err))
            sys.exit(2)

        self.tx_storage = self.manager.tx_storage
        self.wallet = self.manager.wallet
        self.start_manager()

        if self._args.stratum:
            self.reactor.listenTCP(self._args.stratum, self.manager.stratum_factory)

        from hathor.conf import HathorSettings
        from hathor.feature_activation.feature_service import FeatureService
        settings = HathorSettings()

        feature_service = FeatureService(
            feature_settings=settings.FEATURE_ACTIVATION,
            tx_storage=self.manager.tx_storage
        )

        if register_resources:
            resources_builder = ResourcesBuilder(self.manager, self._args, builder.event_ws_factory, feature_service)
            status_server = resources_builder.build()
            if self._args.status:
                self.reactor.listenTCP(self._args.status, status_server)

        from hathor.builder.builder import BuildArtifacts
        self.artifacts = BuildArtifacts(
            peer_id=self.manager.my_peer,
            settings=settings,
            rng=self.manager.rng,
            reactor=self.manager.reactor,
            manager=self.manager,
            p2p_manager=self.manager.connections,
            pubsub=self.manager.pubsub,
            consensus=self.manager.consensus_algorithm,
            tx_storage=self.manager.tx_storage,
            indexes=self.manager.tx_storage.indexes,
            wallet=self.manager.wallet,
            rocksdb_storage=getattr(builder, 'rocksdb_storage', None),
            stratum_factory=self.manager.stratum_factory,
            feature_service=feature_service
        )

    def start_sentry_if_possible(self) -> None:
        """Start Sentry integration if possible."""
        if not self._args.sentry_dsn:
            return
        self.log.info('Starting Sentry', dsn=self._args.sentry_dsn)
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
            dsn=self._args.sentry_dsn,
            release=hathor.__version__,
            environment=settings.NETWORK_NAME,
        )

    def start_manager(self) -> None:
        self.start_sentry_if_possible()
        self.manager.start()

    def register_signal_handlers(self) -> None:
        """Register signal handlers."""
        import signal
        sigusr1 = getattr(signal, 'SIGUSR1', None)
        if sigusr1 is not None:
            # USR1 is available in this OS.
            signal.signal(sigusr1, self.signal_usr1_handler)

    def signal_usr1_handler(self, sig: int, frame: Any) -> None:
        """Called when USR1 signal is received."""
        self.log.warn('USR1 received. Killing all connections...')
        if self.manager and self.manager.connections:
            self.manager.connections.disconnect_all_peers(force=True)

    def check_unsafe_arguments(self) -> None:
        unsafe_args_found = []
        for arg_cmdline, arg_test_fn in self.UNSAFE_ARGUMENTS:
            if arg_test_fn(self._args):
                unsafe_args_found.append(arg_cmdline)

        if self._args.unsafe_mode is None:
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

            if self._args.unsafe_mode != settings.NETWORK_NAME:
                message.extend([
                    f'Unsafe mode enabled for wrong network ({self._args.unsafe_mode} != {settings.NETWORK_NAME}).',
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

    def check_python_version(self) -> None:
        MIN_VER = (3, 8)
        RECOMMENDED_VER = (3, 9)
        cur = sys.version_info
        min_pretty = '.'.join(map(str, MIN_VER))
        cur_pretty = '.'.join(map(str, cur))
        recommended_pretty = '.'.join(map(str, RECOMMENDED_VER))
        if cur < MIN_VER:
            self.log.critical('\n'.join([
                '',
                '********************************************************',
                f'The detected Python version {cur_pretty} is not supported anymore.',
                f'The minimum supported Python version is be {min_pretty}',
                f'The recommended Python version is {recommended_pretty}',
                '********************************************************',
                '',
            ]))
            sys.exit(-1)

    def __init__(self, *, argv=None):
        self.log = logger.new()

        if argv is None:
            import sys
            argv = sys.argv[1:]

        self.parser = self.create_parser()
        raw_args = self.parse_args(argv)

        self._args = RunNodeArgs.parse_obj(vars(raw_args))

        if self._args.config_yaml:
            os.environ['HATHOR_CONFIG_YAML'] = self._args.config_yaml
        elif self._args.testnet:
            os.environ['HATHOR_CONFIG_YAML'] = TESTNET_SETTINGS_FILEPATH

        try:
            HathorSettings()
        except (TypeError, ValidationError) as e:
            raise PreInitializationError(
                'An error was found while trying to initialize HathorSettings. See above for details.'
            ) from e

        self.prepare()
        self.register_signal_handlers()
        if self._args.sysctl:
            self.init_sysctl(self._args.sysctl)

    def init_sysctl(self, description: str) -> None:
        """Initialize sysctl and listen for connections.

        Examples of description:
        - tcp:5000
        - tcp:5000:interface=127.0.0.1
        - unix:/path/sysctl.sock
        - unix:/path/sysctl.sock:mode=660

        For the full documentation, check the link below:
        https://docs.twisted.org/en/stable/api/twisted.internet.endpoints.html#serverFromString
        """
        from twisted.internet.endpoints import serverFromString

        from hathor.builder.sysctl_builder import SysctlBuilder
        from hathor.sysctl.factory import SysctlFactory

        builder = SysctlBuilder(self.artifacts)
        root = builder.build()

        factory = SysctlFactory(root)
        endpoint = serverFromString(self.reactor, description)
        endpoint.listen(factory)

    def parse_args(self, argv: list[str]) -> Namespace:
        return self.parser.parse_args(argv)

    def run(self) -> None:
        self.reactor.run()


def main():
    RunNode().run()
