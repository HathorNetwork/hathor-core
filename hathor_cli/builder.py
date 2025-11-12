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
import os
import platform
import sys
from typing import Any, Optional

from structlog import get_logger

from hathor_cli.run_node_args import RunNodeArgs
from hathor_cli.side_dag import SideDagArgs
from hathor.builder.builder import Builder
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.exception import BuilderError
from hathor.indexes import IndexesManager
from hathor.manager import HathorManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerEndpoint
from hathor.p2p.utils import discover_hostname, get_genesis_short_hash
from hathor.pubsub import PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.wallet import BaseWallet

logger = get_logger()

DEFAULT_CACHE_SIZE: int = 100000


class CliBuilder:
    """CliBuilder builds the core objects from args.

    TODO Refactor to use Builder. It could even be ported to a Builder.from_args classmethod.
    """
    def __init__(self, args: RunNodeArgs) -> None:
        self.log = logger.new()
        self._args = args
        self.event_ws_factory = None

    def check_or_raise(self, condition: bool, message: str) -> None:
        """Will exit printing `message` if `condition` is False."""
        if not condition:
            raise BuilderError(message)

    def check_or_warn(self, condition: bool, message: str) -> None:
        """Will log a warning `message` if `condition` is False."""
        if not condition:
            self.log.warn(message)

    def create_manager(self, reactor: Reactor) -> HathorManager:
        import hathor
        from hathor.conf.get_settings import get_global_settings, get_settings_source
        from hathor.daa import TestMode
        from hathor.p2p.netfilter.utils import add_peer_id_blacklist
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery

        settings = get_global_settings()

        # only used for logging its location
        settings_source = get_settings_source()

        self.log = logger.new()
        self.reactor = reactor

        # Create or load peer
        peer: PrivatePeer
        if self._args.peer:
            peer = PrivatePeer.create_from_json_path(self._args.peer)
        else:
            peer = PrivatePeer.auto_generated()
        python = f'{platform.python_version()}-{platform.python_implementation()}'

        self.log.info(
            'hathor-core v{hathor}',
            hathor=hathor.__version__,
            pid=os.getpid(),
            genesis=get_genesis_short_hash(),
            my_peer_id=str(peer.id),
            python=python,
            platform=platform.platform(),
            settings=settings_source,
            reactor_type=type(reactor).__name__,
        )

        # Validate deprecated parameters
        memory_msg = 'is deprecated. use --temp-data instead'
        self.check_or_raise(not self._args.memory_storage, f'--memory-storage {memory_msg}')
        self.check_or_raise(not self._args.memory_indexes, f'--memory-indexes {memory_msg}')
        self.check_or_raise(bool(self._args.data) or self._args.temp_data, 'either --data or --temp-data is expected')
        self.check_or_raise(not self._args.sync_bridge, '--sync-bridge was removed')
        self.check_or_raise(not self._args.sync_v1_only, '--sync-v1-only was removed')
        self.check_or_raise(not self._args.x_sync_bridge, '--x-sync-bridge was removed')
        self.check_or_raise(not self._args.x_sync_v1_only, '--x-sync-v1-only was removed')
        self.check_or_warn(not self._args.sync_v2_only, '--sync-v2-only is the default, this parameter has no effect')
        self.check_or_warn(not self._args.x_remove_sync_v1, '--x-remove-sync-v1 is deprecated and has no effect')
        self.check_or_warn(not self._args.x_sync_v2_only, '--x-sync-v2-only is deprecated and will be removed')

        if self._args.cache:
            self.log.warn('--cache is now the default and will be removed')

        if self._args.disable_cache:
            self.check_or_raise(self._args.cache_size is None, 'cannot use --disable-cache with --cache-size')
            self.check_or_raise(self._args.cache_interval is None, 'cannot use --disable-cache with --cache-interval')

        if self._args.x_enable_event_queue:
            self.log.warn('--x-enable-event-queue is deprecated and will be removed, use --enable-event-queue instead')

        # Initialize Builder
        builder = Builder()
        builder.set_settings(settings)
        builder.set_reactor(reactor)
        builder.set_peer(peer)

        # Configure storage
        if self._args.data:
            builder.set_rocksdb_path(self._args.data)
        # else: temp_data means use temporary storage (default in Builder)

        if self._args.rocksdb_cache:
            builder.set_rocksdb_cache_capacity(self._args.rocksdb_cache)

        # Configure cache
        if not self._args.disable_cache:
            cache_capacity = self._args.cache_size if self._args.cache_size is not None else DEFAULT_CACHE_SIZE
            builder.use_tx_storage_cache(capacity=cache_capacity)
            # Note: cache_interval is not supported by Builder, will need to set it post-build

        # Configure indexes
        if self._args.wallet_index:
            self.log.debug('enable wallet indexes')
            builder.enable_wallet_index()

        if self._args.utxo_index:
            self.log.debug('enable utxo index')
            builder.enable_utxo_index()

        if self._args.nc_indexes:
            self.log.debug('enable nano indexes')
            builder.enable_nc_indexes()

        # Configure event queue
        if self._args.x_enable_event_queue or self._args.enable_event_queue:
            builder.enable_event_queue()
            self.log.info('--enable-event-queue flag provided. '
                          'The events detected by the full node will be stored and can be retrieved by clients')

        # Configure stratum
        if self._args.stratum:
            builder.enable_stratum_server()

        # Configure network
        if self._args.x_enable_ipv6:
            builder.enable_ipv6()

        if self._args.x_disable_ipv4:
            builder.disable_ipv4()

        # Configure feature signaling
        if self._args.signal_support or self._args.signal_not_support:
            builder.set_features(
                support_features=self._args.signal_support,
                not_support_features=self._args.signal_not_support
            )

        # Configure NC logs
        if self._args.nc_exec_logs:
            builder.set_nc_log_config(self._args.nc_exec_logs)

        # Configure POA signer
        if settings.CONSENSUS_ALGORITHM.is_poa():
            assert isinstance(self._args, SideDagArgs)
            if self._args.poa_signer_file:
                from hathor.consensus.poa import PoaSignerFile
                poa_signer_file = PoaSignerFile.parse_file(self._args.poa_signer_file)
                builder.set_poa_signer(poa_signer_file.get_signer())

        # Configure wallet
        self.wallet = None
        if self._args.wallet:
            if self._args.wallet == 'hd':
                wallet_kwargs: dict[str, Any] = {
                    'words': self._args.words,
                }
                if self._args.passphrase:
                    wallet_passphrase = getpass.getpass(prompt='HD Wallet passphrase:')
                    wallet_kwargs['passphrase'] = wallet_passphrase.encode()
                if self._args.data:
                    wallet_kwargs['directory'] = self._args.data
                from hathor.wallet import HDWallet
                self.wallet = HDWallet(**wallet_kwargs)
                builder.set_wallet(self.wallet)
            elif self._args.wallet == 'keypair':
                print('Using KeyPairWallet')
                unlock_password = None
                if self._args.unlock_wallet:
                    wallet_passwd = getpass.getpass(prompt='Wallet password:')
                    unlock_password = wallet_passwd.encode()
                wallet_directory = self._args.data if self._args.data else None
                if wallet_directory:
                    builder.enable_keypair_wallet(directory=wallet_directory, unlock=unlock_password)
                else:
                    # Create a wallet without directory (will use default)
                    from hathor.wallet import Wallet
                    self.wallet = Wallet()
                    self.wallet.flush_to_disk_interval = 5
                    if unlock_password:
                        self.wallet.unlock(unlock_password)
                    builder.set_wallet(self.wallet)
            else:
                raise BuilderError('Invalid type of wallet')

        # Handle components that need manual creation for debug parameters
        test_mode = TestMode.DISABLED
        if self._args.test_mode_tx_weight:
            test_mode = TestMode.TEST_TX_WEIGHT
            daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=test_mode)
            builder.set_daa(daa)

        # Configure debug parameters
        if self._args.nc_exec_fail_trace:
            builder.set_nc_exec_fail_trace(True)

        if self._args.log_vertex_bytes:
            builder.set_log_vertex_bytes(True)

        # Set command line for environment info
        builder.set_cmdline(str(self._args))

        # Build once
        artifacts = builder.build()
        self.manager = artifacts.manager
        self.tx_storage = artifacts.tx_storage
        self.rocksdb_storage = artifacts.rocksdb_storage
        if not self.wallet:
            self.wallet = artifacts.wallet

        # Get hostname for manager
        hostname = self.get_hostname()
        if hostname:
            self.manager._hostname = hostname

        # Set event_ws_factory for tests/external access
        if self._args.x_enable_event_queue or self._args.enable_event_queue:
            self.event_ws_factory = self.manager._event_manager._event_ws_factory

        # Post-build wallet configuration
        if self.wallet and self._args.wallet == 'keypair':
            self.wallet.flush_to_disk_interval = 5

        if self.wallet and self._args.test_mode_tx_weight:
            self.wallet.test_mode = True

        # Log storage and cache info
        self.log.info('with storage', storage_class=type(self.tx_storage).__name__, path=self._args.data)
        if not self._args.disable_cache:
            from hathor.transaction.storage import TransactionCacheStorage
            if isinstance(self.tx_storage, TransactionCacheStorage):
                if self._args.cache_interval:
                    self.tx_storage.interval = self._args.cache_interval
                self.log.info('with cache', capacity=self.tx_storage.capacity, interval=self.tx_storage.interval)
        self.log.info('with indexes', indexes_class=type(self.tx_storage.indexes).__name__)

        if self.wallet:
            self.log.info('with wallet', wallet=self.wallet, path=self._args.data)

        # IPython kernel setup
        if self._args.x_ipython_kernel:
            self.check_or_raise(self._args.x_asyncio_reactor,
                                '--x-ipython-kernel must be used with --x-asyncio-reactor')
            self._start_ipykernel()

        # Post-build manager configuration
        if self._args.data:
            self.manager.set_cmd_path(self._args.data)

        if self._args.allow_mining_without_peers:
            self.manager.allow_mining_without_peers()

        if self._args.x_localhost_only:
            self.manager.connections.localhost_only = True

        # Configure peer discovery
        p2p_manager = artifacts.p2p_manager
        dns_hosts = []
        if settings.BOOTSTRAP_DNS:
            dns_hosts.extend(settings.BOOTSTRAP_DNS)

        if self._args.dns:
            dns_hosts.extend(self._args.dns)

        if dns_hosts:
            p2p_manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

        if self._args.bootstrap:
            entrypoints = [PeerEndpoint.parse(desc) for desc in self._args.bootstrap]
            p2p_manager.add_peer_discovery(BootstrapPeerDiscovery(entrypoints))

        for description in self._args.listen:
            p2p_manager.add_listen_address_description(description)

        if self._args.peer_id_blacklist:
            self.log.info('with peer id blacklist', blacklist=self._args.peer_id_blacklist)
            add_peer_id_blacklist(self._args.peer_id_blacklist)

        return self.manager

    def enable_wallet_index(self, indexes: IndexesManager, pubsub: PubSubManager) -> None:
        self.log.debug('enable wallet indexes')
        indexes.enable_address_index(pubsub)
        indexes.enable_tokens_index()

    def get_hostname(self) -> Optional[str]:
        if self._args.hostname and self._args.auto_hostname:
            print('You cannot use --hostname and --auto-hostname together.')
            sys.exit(-1)

        if not self._args.auto_hostname:
            hostname = self._args.hostname
        else:
            print('Trying to discover your hostname...')
            hostname = discover_hostname()
            if not hostname:
                print('Aborting because we could not discover your hostname.')
                print('Try again or run without --auto-hostname.')
                sys.exit(-1)
            print('Hostname discovered and set to {}'.format(hostname))
        return hostname

    def create_wallet(self) -> BaseWallet:
        if self._args.wallet == 'hd':
            kwargs: dict[str, Any] = {
                'words': self._args.words,
            }

            if self._args.passphrase:
                wallet_passphrase = getpass.getpass(prompt='HD Wallet passphrase:')
                kwargs['passphrase'] = wallet_passphrase.encode()

            if self._args.data:
                kwargs['directory'] = self._args.data

            return HDWallet(**kwargs)
        elif self._args.wallet == 'keypair':
            print('Using KeyPairWallet')
            if self._args.data:
                wallet = Wallet(directory=self._args.data)
            else:
                wallet = Wallet()

            wallet.flush_to_disk_interval = 5  # seconds

            if self._args.unlock_wallet:
                wallet_passwd = getpass.getpass(prompt='Wallet password:')
                wallet.unlock(wallet_passwd.encode())

            return wallet
        else:
            raise BuilderError('Invalid type of wallet')

    def _start_ipykernel(self) -> None:
        # breakpoints are not expected to be used with the embeded ipykernel, to prevent this warning from being
        # unnecessarily annoying, PYDEVD_DISABLE_FILE_VALIDATION should be set to 1 before debugpy is imported, or in
        # practice, before importing hathor.ipykernel, if for any reason support for breakpoints is needed, the flag
        # -Xfrozen_modules=off has to be passed to the python interpreter
        # see:
        # https://github.com/microsoft/debugpy/blob/main/src/debugpy/_vendored/pydevd/pydevd_file_utils.py#L587-L592
        os.environ['PYDEVD_DISABLE_FILE_VALIDATION'] = '1'
        from hathor.ipykernel import embed_kernel
        embed_kernel(self.manager, runtime_dir=self._args.data, extra_ns=dict(run_node=self))
