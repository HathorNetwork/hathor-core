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
import tempfile
from argparse import SUPPRESS, ArgumentParser, Namespace
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional

from pydantic import ValidationError
from structlog import get_logger

logger = get_logger()
# LOGGING_CAPTURE_STDOUT = True

if TYPE_CHECKING:
    from hathor_cli.run_node_args import RunNodeArgs
    from hathor.sysctl.runner import SysctlRunner


@contextmanager
def temp_fifo(filename: str, tempdir: str | None) -> Iterator[None]:
    """Context Manager for creating named pipes."""
    mkfifo = getattr(os, 'mkfifo', None)
    if mkfifo is None:
        raise AttributeError('mkfifo is not available')

    mkfifo(filename, mode=0o666)
    try:
        yield None
    finally:
        os.unlink(filename)
        if tempdir is not None:
            os.rmdir(tempdir)


class RunNode:
    UNSAFE_ARGUMENTS: list[tuple[str, Callable[['RunNodeArgs'], bool]]] = [
        ('--test-mode-tx-weight', lambda args: bool(args.test_mode_tx_weight)),
        ('--enable-crash-api', lambda args: bool(args.enable_crash_api)),
        ('--sync-bridge', lambda args: bool(args.sync_bridge)),
        ('--sync-v1-only', lambda args: bool(args.sync_v1_only)),
        ('--x-sync-bridge', lambda args: bool(args.x_sync_bridge)),
        ('--x-sync-v1-only', lambda args: bool(args.x_sync_v1_only)),
        ('--x-sync-v2-only', lambda args: bool(args.x_sync_v2_only)),
        ('--x-asyncio-reactor', lambda args: bool(args.x_asyncio_reactor)),
        ('--x-ipython-kernel', lambda args: bool(args.x_ipython_kernel)),
    ]

    env_vars_prefix: str | None = None

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        """
        Create a new parser with the run_node CLI arguments.
        Arguments must also be added to hathor_cli.run_node_args.RunNodeArgs
        """
        from hathor_cli.util import create_parser
        from hathor.feature_activation.feature import Feature
        from hathor.nanocontracts.nc_exec_logs import NCLogConfig
        parser = create_parser(prefix=cls.env_vars_prefix)

        parser.add_argument('--hostname', help='Hostname used to be accessed by other peers')
        parser.add_argument('--auto-hostname', action='store_true', help='Try to discover the hostname automatically')
        parser.add_argument('--unsafe-mode',
                            help='Enable unsafe parameters. **NEVER USE IT IN PRODUCTION ENVIRONMENT**')

        netargs = parser.add_mutually_exclusive_group()
        netargs.add_argument('--nano-testnet', action='store_true', help='Connect to Hathor nano-testnet')
        netargs.add_argument('--testnet', action='store_true', help='Connect to Hathor the default testnet'
                             ' (currently testnet-india)')
        netargs.add_argument('--testnet-hotel', action='store_true', help=SUPPRESS)
        netargs.add_argument('--testnet-golf', action='store_true', help=SUPPRESS)
        netargs.add_argument('--localnet', action='store_true', help='Create a localnet with default configuration.')

        parser.add_argument('--test-mode-tx-weight', action='store_true',
                            help='Reduces tx weight to 1 for testing purposes')
        parser.add_argument('--dns', action='append', help='Seed DNS')
        parser.add_argument('--peer', help='json file with peer info')
        parser.add_argument('--sysctl',
                            help='Endpoint description (eg: unix:/path/sysctl.sock, tcp:5000:interface:127.0.0.1)')
        parser.add_argument('--sysctl-init-file',
                            help='File path to the sysctl.txt init file (eg: conf/sysctl.txt)')
        parser.add_argument('--listen', action='append', default=[],
                            help='Address to listen for new connections (eg: tcp:8000)')
        parser.add_argument('--bootstrap', action='append', help='Address to connect to (eg: tcp:127.0.0.1:8000')
        parser.add_argument('--status', type=int, help='Port to run status server')
        parser.add_argument('--x-status-ipv6-interface', help='IPv6 interface to bind the status server')
        parser.add_argument('--stratum', type=int, help='Port to run stratum server')
        parser.add_argument('--x-stratum-ipv6-interface', help='IPv6 interface to bind the stratum server')
        data_group = parser.add_mutually_exclusive_group()
        data_group.add_argument('--data', help='Data directory')
        data_group.add_argument('--temp-data', action='store_true',
                                help='Automatically create storage in a temporary directory')
        parser.add_argument('--memory-storage', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--memory-indexes', action='store_true', help=SUPPRESS)  # deprecated
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
        parser.add_argument('--nc-indexes', action='store_true',
                            help='Enable indexes related to nano contracts')
        parser.add_argument('--prometheus', action='store_true', help='Send metric data to Prometheus')
        parser.add_argument('--prometheus-prefix', default='',
                            help='A prefix that will be added in all Prometheus metrics')
        cache_args = parser.add_mutually_exclusive_group()
        cache_args.add_argument('--cache', action='store_true', help=SUPPRESS)  # moved to --disable-cache
        cache_args.add_argument('--disable-cache', action='store_true', help='Disable cache for tx storage')
        parser.add_argument('--cache-size', type=int, help='Number of txs to keep on cache')
        parser.add_argument('--cache-interval', type=int, help='Cache flush interval')
        parser.add_argument('--recursion-limit', type=int, help='Set python recursion limit')
        parser.add_argument('--allow-mining-without-peers', action='store_true', help='Allow mining without peers')
        parser.add_argument('--procname-prefix', help='Add a prefix to the process name', default='')
        parser.add_argument('--allow-non-standard-script', action='store_true', help='Accept non-standard scripts on '
                            '/push-tx API')
        parser.add_argument('--max-output-script-size', type=int, default=None, help='Custom max accepted script size '
                            'on /push-tx API')
        parser.add_argument('--sentry-dsn', help='Sentry DSN')
        parser.add_argument('--enable-debug-api', action='store_true', help='Enable _debug/* endpoints')
        parser.add_argument('--enable-crash-api', action='store_true', help='Enable _crash/* endpoints')
        parser.add_argument('--sync-bridge', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--sync-v1-only', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--sync-v2-only', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--x-remove-sync-v1', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--x-sync-v1-only', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--x-sync-v2-only', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--x-sync-bridge', action='store_true', help=SUPPRESS)  # deprecated
        parser.add_argument('--x-localhost-only', action='store_true', help='Only connect to peers on localhost')
        parser.add_argument('--x-enable-event-queue', action='store_true',
                            help='Deprecated: use --enable-event-queue instead.')
        parser.add_argument('--enable-event-queue', action='store_true', help='Enable event queue mechanism')
        parser.add_argument('--peer-id-blacklist', action='extend', default=[], nargs='+', type=str,
                            help='Peer IDs to forbid connection')
        parser.add_argument('--config-yaml', type=str, help='Configuration yaml filepath')
        possible_features = [feature.value for feature in Feature]
        parser.add_argument('--signal-support', default=[], action='append', choices=possible_features,
                            help=f'Signal support for a feature. One of {possible_features}')
        parser.add_argument('--signal-not-support', default=[], action='append', choices=possible_features,
                            help=f'Signal not support for a feature. One of {possible_features}')
        parser.add_argument('--x-asyncio-reactor', action='store_true',
                            help='Use asyncio reactor instead of Twisted\'s default.')
        # XXX: this is temporary, should be added as a sysctl instead before merging
        parser.add_argument('--x-ipython-kernel', action='store_true',
                            help='Launch embedded IPython kernel for remote debugging')
        parser.add_argument('--log-vertex-bytes', action='store_true',
                            help='Log tx bytes for debugging')
        parser.add_argument('--disable-ws-history-streaming', action='store_true',
                            help='Disable websocket history streaming API')
        parser.add_argument('--x-enable-ipv6', action='store_true',
                            help='Enables listening on IPv6 interface and connecting to IPv6 peers')
        parser.add_argument('--x-disable-ipv4', action='store_true',
                            help='Disables connecting to IPv4 peers')

        parser.add_argument("--x-p2p-whitelist", help="Add whitelist to follow from since boot.")

        possible_nc_exec_logs = [config.value for config in NCLogConfig]
        parser.add_argument('--nc-exec-logs', default=NCLogConfig.NONE, choices=possible_nc_exec_logs,
                            help=f'Enable saving Nano Contracts execution logs. One of {possible_nc_exec_logs}')
        parser.add_argument('--nc-exec-fail-trace', action='store_true', help=SUPPRESS)
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        import resource

        from setproctitle import setproctitle

        setproctitle('{}hathor-core'.format(self._args.procname_prefix))

        if self._args.recursion_limit:
            sys.setrecursionlimit(self._args.recursion_limit)
        else:
            sys.setrecursionlimit(5000)

        (nofile_soft, _) = resource.getrlimit(resource.RLIMIT_NOFILE)
        if nofile_soft < 256:
            print('Maximum number of open file descriptors is too low. Minimum required is 256.')
            sys.exit(-2)

        self.validate_args()
        self.check_unsafe_arguments()
        self.check_python_version()

        from hathor.reactor import initialize_global_reactor
        reactor = initialize_global_reactor(use_asyncio_reactor=self._args.x_asyncio_reactor)
        self.reactor = reactor

        from hathor.builder import ResourcesBuilder
        from hathor.exception import BuilderError
        from hathor_cli.builder import CliBuilder
        builder = CliBuilder(self._args)
        try:
            self.manager = builder.create_manager(reactor)
        except BuilderError as err:
            self.log.error(str(err))
            sys.exit(2)

        self.tx_storage = self.manager.tx_storage
        self.wallet = self.manager.wallet

        if self._args.stratum:
            assert self.manager.stratum_factory is not None

            if self._args.x_enable_ipv6:
                interface = self._args.x_stratum_ipv6_interface or '::0'
                # Linux by default will map IPv4 to IPv6, so listening only in the IPv6 interface will be
                # enough to handle IPv4 connections. There is a kernel parameter that controls this behavior:
                # https://sysctl-explorer.net/net/ipv6/bindv6only/
                self.reactor.listenTCP(self._args.stratum, self.manager.stratum_factory, interface=interface)
            else:
                self.reactor.listenTCP(self._args.stratum, self.manager.stratum_factory)

        from hathor.conf.get_settings import get_global_settings
        settings = get_global_settings()

        if register_resources:
            resources_builder = ResourcesBuilder(
                self.manager,
                self._args,
                builder.event_ws_factory,
                builder.feature_service
            )
            status_server = resources_builder.build()
            if self._args.status:
                assert status_server is not None

                if self._args.x_enable_ipv6:
                    interface = self._args.x_status_ipv6_interface or '::0'
                    self.reactor.listenTCP(self._args.status, status_server, interface=interface)
                else:
                    self.reactor.listenTCP(self._args.status, status_server)

        self.start_manager()

        from hathor.builder.builder import BuildArtifacts
        self.artifacts = BuildArtifacts(
            peer=self.manager.my_peer,
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
            rocksdb_storage=builder.rocksdb_storage,
            stratum_factory=self.manager.stratum_factory,
            feature_service=self.manager.vertex_handler._feature_service,
            bit_signaling_service=self.manager._bit_signaling_service,
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
        from hathor.conf.get_settings import get_global_settings
        settings = get_global_settings()
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
        sigusr2 = getattr(signal, 'SIGUSR2', None)
        if sigusr2 is not None:
            # USR1 is available in this OS.
            signal.signal(sigusr2, self.signal_usr2_handler)

    def signal_usr1_handler(self, sig: int, frame: Any) -> None:
        """Called when USR1 signal is received."""
        try:
            self.log.warn('USR1 received.')
            self.manager.connections.reload_entrypoints_and_connections()
        except Exception:
            # see: https://docs.python.org/3/library/signal.html#note-on-signal-handlers-and-exceptions
            self.log.error('prevented exception from escaping the signal handler', exc_info=True)

    def signal_usr2_handler(self, sig: int, frame: Any) -> None:
        """Called when USR2 signal is received."""
        try:
            self.log.warn('USR2 received.')
            self.run_sysctl_from_signal()
        except Exception:
            # see: https://docs.python.org/3/library/signal.html#note-on-signal-handlers-and-exceptions
            self.log.error('prevented exception from escaping the signal handler', exc_info=True)

    def run_sysctl_from_signal(self) -> None:
        """Block the main loop, get commands from a named pipe and execute then using sysctl."""
        from hathor.sysctl.exception import (
            SysctlEntryNotFound,
            SysctlException,
            SysctlReadOnlyEntry,
            SysctlRunnerException,
            SysctlWriteOnlyEntry,
        )

        runner = self.get_sysctl_runner()

        if self._args.data is not None:
            basedir = self._args.data
            tempdir = None
        else:
            basedir = tempfile.mkdtemp()
            tempdir = basedir

        filename = os.path.join(basedir, f'SIGUSR2-{os.getpid()}.pipe')
        if os.path.exists(filename):
            self.log.warn('[USR2] Pipe already exists.', pipe=filename)
            return

        with temp_fifo(filename, tempdir):
            self.log.warn('[USR2] Main loop paused, awaiting command to proceed.', pipe=filename)

            fp = open(filename, 'r')
            try:
                lines = fp.readlines()
            finally:
                fp.close()

            for cmd in lines:
                cmd = cmd.strip()
                self.log.warn('[USR2] Command received ', cmd=cmd)

                try:
                    output = runner.run(cmd, require_signal_handler_safe=True)
                    self.log.warn('[USR2] Output', output=output)
                except SysctlEntryNotFound:
                    path, _, _ = runner.get_line_parts(cmd)
                    self.log.warn('[USR2] Error', errmsg=f'{path} not found')
                except SysctlReadOnlyEntry:
                    path, _, _ = runner.get_line_parts(cmd)
                    self.log.warn('[USR2] Error', errmsg=f'cannot write to {path}')
                except SysctlWriteOnlyEntry:
                    path, _, _ = runner.get_line_parts(cmd)
                    self.log.warn('[USR2] Error', errmsg=f'cannot read from {path}')
                except SysctlException as e:
                    self.log.warn('[USR2] Error', errmsg=str(e))
                except ValidationError as e:
                    self.log.warn('[USR2] Error', errmsg=str(e))
                except SysctlRunnerException as e:
                    self.log.warn('[USR2] Error', errmsg=str(e))

    def validate_args(self) -> None:
        if self._args.x_disable_ipv4 and not self._args.x_enable_ipv6:
            self.log.critical('You must enable IPv6 if you disable IPv4.')
            sys.exit(-1)

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

            from hathor.conf.get_settings import get_global_settings
            settings = get_global_settings()

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
        # comments to help grep's
        MIN_VER = (3, 11)  # Python-3.11
        MIN_STABLE = (3, 12)  # Python-3.12
        RECOMMENDED_VER = (3, 12)  # Python-3.12
        cur = sys.version_info
        cur_pretty = '.'.join(map(str, cur))
        min_pretty = '.'.join(map(str, MIN_VER))
        min_stable_pretty = '.'.join(map(str, MIN_STABLE))
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
        elif cur < MIN_STABLE:
            self.log.warning('\n'.join([
                '',
                '********************************************************',
                f'The detected Python version {cur_pretty} is deprecated and support for it will be removed in the'
                ' next release.',
                f'The minimum supported Python version will be {min_stable_pretty}',
                f'The recommended Python version is {recommended_pretty}',
                '********************************************************',
                '',
            ]))

    def __init__(self, *, argv=None):
        from hathorlib.conf import (
            LOCALNET_SETTINGS_FILEPATH,
            NANO_TESTNET_SETTINGS_FILEPATH,
            TESTNET_INDIA_SETTINGS_FILEPATH,
        )
        from hathor.conf.get_settings import get_global_settings
        self.log = logger.new()

        if argv is None:
            import sys
            argv = sys.argv[1:]

        self.parser = self.create_parser()
        raw_args = self.parse_args(argv)

        self._args = self._parse_args_obj(vars(raw_args))

        if self._args.config_yaml:
            os.environ['HATHOR_CONFIG_YAML'] = self._args.config_yaml
        elif self._args.testnet:
            os.environ['HATHOR_CONFIG_YAML'] = TESTNET_INDIA_SETTINGS_FILEPATH
        elif self._args.testnet_hotel:
            self.log.critical('testnet-hotel is not supported anymore')
            sys.exit(-1)
        elif self._args.testnet_golf:
            self.log.critical('testnet-golf is not supported anymore')
            sys.exit(-1)
        elif self._args.nano_testnet:
            os.environ['HATHOR_CONFIG_YAML'] = NANO_TESTNET_SETTINGS_FILEPATH
        elif self._args.localnet:
            os.environ['HATHOR_CONFIG_YAML'] = LOCALNET_SETTINGS_FILEPATH

        try:
            get_global_settings()
        except (TypeError, ValidationError) as e:
            from hathor.exception import PreInitializationError
            raise PreInitializationError(
                'An error was found while trying to initialize HathorSettings. See above for details.'
            ) from e

        self.prepare()
        self.register_signal_handlers()
        if self._args.sysctl:
            self.init_sysctl(self._args.sysctl, self._args.sysctl_init_file)

    def get_sysctl_runner(self) -> 'SysctlRunner':
        """Create and return a SysctlRunner."""
        from hathor.builder.sysctl_builder import SysctlBuilder
        from hathor.sysctl.runner import SysctlRunner

        builder = SysctlBuilder(self.artifacts)
        root = builder.build()
        runner = SysctlRunner(root)
        return runner

    def init_sysctl(self, description: str, sysctl_init_file: Optional[str] = None) -> None:
        """Initialize sysctl, listen for connections and apply settings from config file if required.

        Examples of description:
        - tcp:5000
        - tcp:5000:interface=127.0.0.1
        - unix:/path/sysctl.sock
        - unix:/path/sysctl.sock:mode=660

        For the full documentation, check the link below:
        https://docs.twisted.org/en/stable/api/twisted.internet.endpoints.html#serverFromString
        """
        from twisted.internet.endpoints import serverFromString

        from hathor.sysctl.factory import SysctlFactory
        from hathor.sysctl.init_file_loader import SysctlInitFileLoader

        runner = self.get_sysctl_runner()

        if sysctl_init_file:
            init_file_loader = SysctlInitFileLoader(runner, sysctl_init_file)
            init_file_loader.load()

        factory = SysctlFactory(runner)
        endpoint = serverFromString(self.reactor, description)
        endpoint.listen(factory)

    def parse_args(self, argv: list[str]) -> Namespace:
        return self.parser.parse_args(argv)

    def _parse_args_obj(self, args: dict[str, Any]) -> 'RunNodeArgs':
        from hathor_cli.run_node_args import RunNodeArgs
        return RunNodeArgs.model_validate(args)

    def run(self) -> None:
        self.reactor.run()


def main():
    RunNode().run()
