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
from typing import Any, Callable, List, Tuple

from structlog import get_logger

from hathor.event.storage import EventStorage
from hathor.util import get_environment_info

logger = get_logger()
# LOGGING_CAPTURE_STDOUT = True


class RunNode:
    UNSAFE_ARGUMENTS: List[Tuple[str, Callable[[Namespace], bool]]] = [
        ('--test-mode-tx-weight', lambda args: bool(args.test_mode_tx_weight)),
        ('--enable-crash-api', lambda args: bool(args.enable_crash_api)),
        ('--x-sync-bridge', lambda args: bool(args.x_sync_bridge)),
        ('--x-sync-v2-only', lambda args: bool(args.x_sync_v2_only)),
    ]

    @classmethod
    def create_parser(cls) -> ArgumentParser:
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
        fvargs.add_argument('--x-fast-init-beta', action='store_true', help=SUPPRESS)
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
        parser.add_argument('--x-rocksdb-indexes', action='store_true', help=SUPPRESS)
        parser.add_argument('--x-enable-event-queue', action='store_true', help='Enable event queue mechanism')
        parser.add_argument('--x-retain-events', action='store_true', help='Retain all events in the local database')
        parser.add_argument('--peer-id-blacklist', action='extend', default=[], nargs='+', type=str,
                            help='Peer IDs to forbid connection')
        return parser

    def prepare(self, args: Namespace, *, register_resources: bool = True) -> None:
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

        self.check_unsafe_arguments(args)
        self.check_python_version()

        from hathor.util import reactor
        self.reactor = reactor

        from hathor.builder import CliBuilder
        from hathor.exception import BuilderError
        builder = CliBuilder()
        try:
            self.manager = builder.create_manager(reactor, args)
        except BuilderError as err:
            self.log.error(str(err))
            sys.exit(2)
        self.tx_storage = self.manager.tx_storage
        self.wallet = self.manager.wallet
        self.start_manager(args)
        if register_resources:
            builder.register_resources(args)

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
