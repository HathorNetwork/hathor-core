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
from enum import Enum, auto
from typing import Any, Optional

from structlog import get_logger

from hathor.cli.run_node_args import RunNodeArgs
from hathor.consensus import ConsensusAlgorithm
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.event import EventManager
from hathor.exception import BuilderError
from hathor.execution_manager import ExecutionManager
from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.storage.feature_activation_storage import FeatureActivationStorage
from hathor.indexes import IndexesManager, MemoryIndexesManager, RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import discover_hostname, get_genesis_short_hash
from hathor.pubsub import PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.stratum import StratumFactory
from hathor.util import Random, not_none
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifiers import VertexVerifiers
from hathor.wallet import BaseWallet, HDWallet, Wallet

logger = get_logger()


class SyncChoice(Enum):
    V1_DEFAULT = auto()  # v2 can be enabled in runtime
    V2_DEFAULT = auto()  # v1 can be enabled in runtime
    BRIDGE_DEFAULT = auto()  # either can be disabled in runtime
    V2_ONLY = auto()  # v1 is unavailable, it cannot be enabled in runtime


class CliBuilder:
    """CliBuilder builds the core objects from args.

    TODO Refactor to use Builder. It could even be ported to a Builder.from_args classmethod.
    """
    def __init__(self, args: RunNodeArgs) -> None:
        self.log = logger.new()
        self._args = args

    def check_or_raise(self, condition: bool, message: str) -> None:
        """Will exit printing `message` if `condition` is False."""
        if not condition:
            raise BuilderError(message)

    def create_manager(self, reactor: Reactor) -> HathorManager:
        import hathor
        from hathor.builder import SyncSupportLevel
        from hathor.conf.get_settings import get_global_settings, get_settings_source
        from hathor.daa import TestMode
        from hathor.event.storage import EventMemoryStorage, EventRocksDBStorage, EventStorage
        from hathor.event.websocket.factory import EventWebsocketFactory
        from hathor.p2p.netfilter.utils import add_peer_id_blacklist
        from hathor.p2p.peer_discovery import BootstrapPeerDiscovery, DNSPeerDiscovery
        from hathor.p2p.sync_v1.factory import SyncV11Factory
        from hathor.p2p.sync_v2.factory import SyncV2Factory
        from hathor.p2p.sync_version import SyncVersion
        from hathor.storage import RocksDBStorage
        from hathor.transaction.storage import (
            TransactionCacheStorage,
            TransactionMemoryStorage,
            TransactionRocksDBStorage,
            TransactionStorage,
        )
        from hathor.util import get_environment_info

        settings = get_global_settings()

        # only used for logging its location
        settings_source = get_settings_source()

        self.log = logger.new()
        self.reactor = reactor

        peer_id = self.create_peer_id()

        python = f'{platform.python_version()}-{platform.python_implementation()}'

        self.log.info(
            'hathor-core v{hathor}',
            hathor=hathor.__version__,
            pid=os.getpid(),
            genesis=get_genesis_short_hash(),
            my_peer_id=str(peer_id.id),
            python=python,
            platform=platform.platform(),
            settings=settings_source,
            reactor_type=type(reactor).__name__,
        )

        # XXX Remove this protection after Nano Contracts are launched.
        if settings.NETWORK_NAME not in {'nano-testnet-alpha', 'unittests'}:
            # Add protection to prevent enabling Nano Contracts due to misconfigurations.
            self.check_or_raise(not settings.ENABLE_NANO_CONTRACTS,
                                'configuration error: NanoContracts can only be enabled on localnets for now')

        tx_storage: TransactionStorage
        event_storage: EventStorage
        indexes: IndexesManager
        feature_storage: FeatureActivationStorage | None = None
        self.rocksdb_storage: Optional[RocksDBStorage] = None
        self.event_ws_factory: Optional[EventWebsocketFactory] = None

        if self._args.memory_storage:
            self.check_or_raise(not self._args.data, '--data should not be used with --memory-storage')
            # if using MemoryStorage, no need to have cache
            indexes = MemoryIndexesManager()
            tx_storage = TransactionMemoryStorage(indexes)
            event_storage = EventMemoryStorage()
            self.check_or_raise(not self._args.x_rocksdb_indexes, 'RocksDB indexes require RocksDB data')
            self.log.info('with storage', storage_class=type(tx_storage).__name__)
        else:
            self.check_or_raise(bool(self._args.data), '--data is expected')
            assert self._args.data is not None
            if self._args.rocksdb_storage:
                self.log.warn('--rocksdb-storage is now implied, no need to specify it')
            cache_capacity = self._args.rocksdb_cache
            self.rocksdb_storage = RocksDBStorage(path=self._args.data, cache_capacity=cache_capacity)

            # Initialize indexes manager.
            if self._args.memory_indexes:
                indexes = MemoryIndexesManager()
            else:
                indexes = RocksDBIndexesManager(self.rocksdb_storage)

            kwargs = {}
            if not self._args.cache:
                # We should only pass indexes if cache is disabled. Otherwise,
                # only TransactionCacheStorage should have indexes.
                kwargs['indexes'] = indexes
            tx_storage = TransactionRocksDBStorage(self.rocksdb_storage, **kwargs)
            event_storage = EventRocksDBStorage(self.rocksdb_storage)
            feature_storage = FeatureActivationStorage(settings=settings, rocksdb_storage=self.rocksdb_storage)

        self.log.info('with storage', storage_class=type(tx_storage).__name__, path=self._args.data)
        if self._args.cache:
            self.check_or_raise(not self._args.memory_storage, '--cache should not be used with --memory-storage')
            tx_storage = TransactionCacheStorage(tx_storage, reactor, indexes=indexes)
            if self._args.cache_size:
                tx_storage.capacity = self._args.cache_size
            if self._args.cache_interval:
                tx_storage.interval = self._args.cache_interval
            self.log.info('with cache', capacity=tx_storage.capacity, interval=tx_storage.interval)
        self.tx_storage = tx_storage
        self.log.info('with indexes', indexes_class=type(tx_storage.indexes).__name__)

        self.wallet = None
        if self._args.wallet:
            self.wallet = self.create_wallet()
            self.log.info('with wallet', wallet=self.wallet, path=self._args.data)

        hostname = self.get_hostname()
        network = settings.NETWORK_NAME

        sync_choice: SyncChoice
        if self._args.sync_bridge:
            self.log.warn('--sync-bridge is the default, this parameter has no effect')
            sync_choice = SyncChoice.BRIDGE_DEFAULT
        elif self._args.sync_v1_only:
            sync_choice = SyncChoice.V1_DEFAULT
        elif self._args.sync_v2_only:
            sync_choice = SyncChoice.V2_DEFAULT
        elif self._args.x_remove_sync_v1:
            sync_choice = SyncChoice.V2_ONLY
        elif self._args.x_sync_bridge:
            self.log.warn('--x-sync-bridge is deprecated and will be removed, use --sync-bridge instead')
            sync_choice = SyncChoice.BRIDGE_DEFAULT
        elif self._args.x_sync_v2_only:
            self.log.warn('--x-sync-v2-only is deprecated and will be removed, use --sync-v2-only instead')
            sync_choice = SyncChoice.V2_DEFAULT
        else:
            sync_choice = SyncChoice.BRIDGE_DEFAULT

        sync_v1_support: SyncSupportLevel
        sync_v2_support: SyncSupportLevel
        match sync_choice:
            case SyncChoice.V1_DEFAULT:
                sync_v1_support = SyncSupportLevel.ENABLED
                sync_v2_support = SyncSupportLevel.DISABLED
            case SyncChoice.V2_DEFAULT:
                sync_v1_support = SyncSupportLevel.DISABLED
                sync_v2_support = SyncSupportLevel.ENABLED
            case SyncChoice.BRIDGE_DEFAULT:
                sync_v1_support = SyncSupportLevel.ENABLED
                sync_v2_support = SyncSupportLevel.ENABLED
            case SyncChoice.V2_ONLY:
                sync_v1_support = SyncSupportLevel.UNAVAILABLE
                sync_v2_support = SyncSupportLevel.ENABLED

        pubsub = PubSubManager(reactor)

        if self._args.x_enable_event_queue:
            self.event_ws_factory = EventWebsocketFactory(
                peer_id=not_none(peer_id.id),
                network=network,
                reactor=reactor,
                event_storage=event_storage
            )

        execution_manager = ExecutionManager(reactor)

        event_manager = EventManager(
            event_storage=event_storage,
            event_ws_factory=self.event_ws_factory,
            pubsub=pubsub,
            reactor=reactor,
            execution_manager=execution_manager,
        )

        if self._args.wallet_index and tx_storage.indexes is not None:
            self.log.debug('enable wallet indexes')
            self.enable_wallet_index(tx_storage.indexes, pubsub)

        if self._args.utxo_index and tx_storage.indexes is not None:
            self.log.debug('enable utxo index')
            tx_storage.indexes.enable_utxo_index()

        full_verification = False
        if self._args.x_full_verification:
            self.check_or_raise(
                not self._args.x_enable_event_queue,
                '--x-full-verification cannot be used with --x-enable-event-queue'
            )
            full_verification = True

        soft_voided_tx_ids = set(settings.SOFT_VOIDED_TX_IDS)
        consensus_algorithm = ConsensusAlgorithm(
            soft_voided_tx_ids,
            pubsub=pubsub,
            execution_manager=execution_manager
        )

        if self._args.x_enable_event_queue:
            self.log.info('--x-enable-event-queue flag provided. '
                          'The events detected by the full node will be stored and can be retrieved by clients')

        self.feature_service = FeatureService(
            feature_settings=settings.FEATURE_ACTIVATION,
            tx_storage=tx_storage
        )

        bit_signaling_service = BitSignalingService(
            feature_settings=settings.FEATURE_ACTIVATION,
            feature_service=self.feature_service,
            tx_storage=tx_storage,
            support_features=self._args.signal_support,
            not_support_features=self._args.signal_not_support,
            feature_storage=feature_storage,
        )

        test_mode = TestMode.DISABLED
        if self._args.test_mode_tx_weight:
            test_mode = TestMode.TEST_TX_WEIGHT
            if self.wallet:
                self.wallet.test_mode = True

        daa = DifficultyAdjustmentAlgorithm(settings=settings, test_mode=test_mode)

        vertex_verifiers = VertexVerifiers.create_defaults(
            settings=settings,
            daa=daa,
            feature_service=self.feature_service
        )
        verification_service = VerificationService(verifiers=vertex_verifiers)

        cpu_mining_service = CpuMiningService()

        p2p_manager = ConnectionsManager(
            reactor,
            network=network,
            my_peer=peer_id,
            pubsub=pubsub,
            ssl=True,
            whitelist_only=False,
            rng=Random(),
        )
        # sync-v1 support:
        if sync_v1_support > SyncSupportLevel.UNAVAILABLE:
            p2p_manager.add_sync_factory(SyncVersion.V1_1, SyncV11Factory(p2p_manager))
        if sync_v1_support is SyncSupportLevel.ENABLED:
            p2p_manager.enable_sync_version(SyncVersion.V1_1)
        # sync-v2 support:
        if sync_v2_support > SyncSupportLevel.UNAVAILABLE:
            p2p_manager.add_sync_factory(SyncVersion.V2, SyncV2Factory(p2p_manager))
        if sync_v2_support is SyncSupportLevel.ENABLED:
            p2p_manager.enable_sync_version(SyncVersion.V2)

        self.manager = HathorManager(
            reactor,
            settings=settings,
            network=network,
            hostname=hostname,
            pubsub=pubsub,
            consensus_algorithm=consensus_algorithm,
            daa=daa,
            peer_id=peer_id,
            tx_storage=tx_storage,
            p2p_manager=p2p_manager,
            event_manager=event_manager,
            wallet=self.wallet,
            checkpoints=settings.CHECKPOINTS,
            environment_info=get_environment_info(args=str(self._args), peer_id=peer_id.id),
            full_verification=full_verification,
            enable_event_queue=self._args.x_enable_event_queue,
            feature_service=self.feature_service,
            bit_signaling_service=bit_signaling_service,
            verification_service=verification_service,
            cpu_mining_service=cpu_mining_service,
            execution_manager=execution_manager,
        )

        if self._args.x_ipython_kernel:
            self.check_or_raise(self._args.x_asyncio_reactor,
                                '--x-ipython-kernel must be used with --x-asyncio-reactor')
            self._start_ipykernel()

        p2p_manager.set_manager(self.manager)

        if self._args.stratum:
            stratum_factory = StratumFactory(self.manager, reactor=reactor)
            self.manager.stratum_factory = stratum_factory
            self.manager.metrics.stratum_factory = stratum_factory

        if self._args.data:
            self.manager.set_cmd_path(self._args.data)

        if self._args.allow_mining_without_peers:
            self.manager.allow_mining_without_peers()

        if self._args.x_localhost_only:
            self.manager.connections.localhost_only = True

        dns_hosts = []
        if settings.BOOTSTRAP_DNS:
            dns_hosts.extend(settings.BOOTSTRAP_DNS)

        if self._args.dns:
            dns_hosts.extend(self._args.dns)

        if dns_hosts:
            p2p_manager.add_peer_discovery(DNSPeerDiscovery(dns_hosts))

        if self._args.bootstrap:
            p2p_manager.add_peer_discovery(BootstrapPeerDiscovery(self._args.bootstrap))

        if self._args.x_rocksdb_indexes:
            self.log.warn('--x-rocksdb-indexes is now the default, no need to specify it')
            if self._args.memory_indexes:
                raise BuilderError('You cannot use --memory-indexes and --x-rocksdb-indexes.')

        if self._args.memory_indexes and self._args.memory_storage:
            self.log.warn('--memory-indexes is implied for memory storage or JSON storage')

        for description in self._args.listen:
            p2p_manager.add_listen_address(description)

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

    def create_peer_id(self) -> PeerId:
        if not self._args.peer:
            peer_id = PeerId()
        else:
            data = json.load(open(self._args.peer, 'r'))
            peer_id = PeerId.create_from_json(data)
        return peer_id

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
