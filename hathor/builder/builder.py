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

import tempfile
from enum import IntEnum
from typing import Any, Callable, NamedTuple, Optional, TypeAlias

from structlog import get_logger

from hathor.checkpoint import Checkpoint
from hathor.conf.settings import HathorSettings as HathorSettingsType
from hathor.consensus import ConsensusAlgorithm
from hathor.consensus.poa import PoaBlockProducer, PoaSigner
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.event import EventManager
from hathor.event.storage import EventRocksDBStorage, EventStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.execution_manager import ExecutionManager
from hathor.feature_activation.bit_signaling_service import BitSignalingService
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.feature_activation.storage.feature_activation_storage import FeatureActivationStorage
from hathor.indexes import IndexesManager, RocksDBIndexesManager
from hathor.manager import HathorManager
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.nanocontracts import NCRocksDBStorageFactory, NCStorageFactory
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.nc_exec_logs import NCLogConfig, NCLogStorage
from hathor.nanocontracts.runner.runner import RunnerFactory
from hathor.nanocontracts.sorter.types import NCSorterCallable
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.pubsub import PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.storage import RocksDBStorage
from hathor.stratum import StratumFactory
from hathor.transaction.json_serializer import VertexJsonSerializer
from hathor.transaction.storage import TransactionRocksDBStorage, TransactionStorage
from hathor.transaction.storage.rocksdb_storage import CacheConfig
from hathor.transaction.vertex_children import RocksDBVertexChildrenService
from hathor.transaction.vertex_parser import VertexParser
from hathor.util import Random, get_environment_info
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifiers import VertexVerifiers
from hathor.vertex_handler import VertexHandler
from hathor.wallet import BaseWallet, Wallet

logger = get_logger()


class SyncSupportLevel(IntEnum):
    UNAVAILABLE = 0  # not possible to enable at runtime
    DISABLED = 1  # available but disabled by default, possible to enable at runtime
    ENABLED = 2  # available and enabled by default, possible to disable at runtime

    @classmethod
    def add_factories(
        cls,
        settings: HathorSettingsType,
        p2p_manager: ConnectionsManager,
        sync_v2_support: 'SyncSupportLevel',
        vertex_parser: VertexParser,
        vertex_handler: VertexHandler,
    ) -> None:
        """Adds the sync factory to the manager according to the support level."""
        from hathor.p2p.sync_v2.factory import SyncV2Factory
        from hathor.p2p.sync_version import SyncVersion

        # sync-v2 support:
        if sync_v2_support > cls.UNAVAILABLE:
            sync_v2_factory = SyncV2Factory(
                settings,
                p2p_manager,
                vertex_parser=vertex_parser,
                vertex_handler=vertex_handler,
            )
            p2p_manager.add_sync_factory(SyncVersion.V2, sync_v2_factory)
        if sync_v2_support == cls.ENABLED:
            p2p_manager.enable_sync_version(SyncVersion.V2)


class BuildArtifacts(NamedTuple):
    """Artifacts created by a builder."""
    peer: PrivatePeer
    settings: HathorSettingsType
    rng: Random
    reactor: Reactor
    manager: HathorManager
    p2p_manager: ConnectionsManager
    pubsub: PubSubManager
    consensus: ConsensusAlgorithm
    tx_storage: TransactionStorage
    feature_service: FeatureService
    bit_signaling_service: BitSignalingService
    indexes: Optional[IndexesManager]
    wallet: Optional[BaseWallet]
    rocksdb_storage: RocksDBStorage
    stratum_factory: Optional[StratumFactory]


_VertexVerifiersBuilder: TypeAlias = Callable[
    [Reactor, HathorSettingsType, DifficultyAdjustmentAlgorithm, FeatureService, TransactionStorage],
    VertexVerifiers
]


class Builder:
    """Builder builds the core objects to run a full node.

    Example:

        builder = Builder()
        builder.enable_event_queue()
        artifacts = builder.build()
    """
    def __init__(self) -> None:
        self.log = logger.new()
        self.artifacts: Optional[BuildArtifacts] = None

        self._settings: Optional[HathorSettingsType] = None
        self._rng: Random = Random()
        self._checkpoints: Optional[list[Checkpoint]] = None
        self._capabilities: Optional[list[str]] = None

        self._peer: Optional[PrivatePeer] = None
        self._cmdline: str = ''

        self._event_manager: Optional[EventManager] = None
        self._enable_event_queue: Optional[bool] = None

        self._support_features: set[Feature] = set()
        self._not_support_features: set[Feature] = set()
        self._feature_service: Optional[FeatureService] = None
        self._bit_signaling_service: Optional[BitSignalingService] = None

        self._daa: Optional[DifficultyAdjustmentAlgorithm] = None
        self._cpu_mining_service: Optional[CpuMiningService] = None

        self._vertex_verifiers: Optional[VertexVerifiers] = None
        self._vertex_verifiers_builder: _VertexVerifiersBuilder | None = None
        self._verification_service: Optional[VerificationService] = None

        self._rocksdb_path: str | tempfile.TemporaryDirectory | None = None
        self._rocksdb_storage: Optional[RocksDBStorage] = None
        self._rocksdb_cache_capacity: Optional[int] = None

        self._tx_storage_cache: bool = False
        self._tx_storage_cache_capacity: Optional[int] = None

        self._indexes_manager: Optional[IndexesManager] = None
        self._tx_storage: Optional[TransactionStorage] = None
        self._event_storage: Optional[EventStorage] = None

        self._reactor: Optional[Reactor] = None
        self._pubsub: Optional[PubSubManager] = None

        self._wallet: Optional[BaseWallet] = None
        self._wallet_directory: Optional[str] = None
        self._wallet_unlock: Optional[bytes] = None

        self._enable_address_index: bool = False
        self._enable_tokens_index: bool = False
        self._enable_utxo_index: bool = False
        self._enable_nc_indexes: bool = False

        self._sync_v2_support: SyncSupportLevel = SyncSupportLevel.ENABLED

        self._enable_stratum_server: Optional[bool] = None

        self._soft_voided_tx_ids: Optional[set[bytes]] = None

        self._execution_manager: ExecutionManager | None = None
        self._vertex_handler: VertexHandler | None = None
        self._vertex_parser: VertexParser | None = None
        self._consensus: ConsensusAlgorithm | None = None
        self._p2p_manager: ConnectionsManager | None = None
        self._poa_signer: PoaSigner | None = None
        self._poa_block_producer: PoaBlockProducer | None = None

        self._enable_ipv6: bool = False
        self._disable_ipv4: bool = False

        self._nc_anti_mev: bool = True

        self._nc_storage_factory: NCStorageFactory | None = None
        self._nc_log_storage: NCLogStorage | None = None
        self._runner_factory: RunnerFactory | None = None
        self._nc_log_config: NCLogConfig = NCLogConfig.NONE

        self._vertex_json_serializer: VertexJsonSerializer | None = None

    def build(self) -> BuildArtifacts:
        if self.artifacts is not None:
            raise ValueError('cannot call build twice')

        if SyncSupportLevel.ENABLED not in {self._sync_v2_support}:
            raise TypeError('you must enable at least one sync version')

        settings = self._get_or_create_settings()
        reactor = self._get_reactor()
        pubsub = self._get_or_create_pubsub()

        peer = self._get_peer()

        execution_manager = self._get_or_create_execution_manager()
        consensus_algorithm = self._get_or_create_consensus()

        p2p_manager = self._get_or_create_p2p_manager()

        wallet = self._get_or_create_wallet()
        event_manager = self._get_or_create_event_manager()
        indexes = self._get_or_create_indexes_manager()
        tx_storage = self._get_or_create_tx_storage()
        rocksdb_storage = self._get_or_create_rocksdb_storage()
        feature_service = self._get_or_create_feature_service()
        bit_signaling_service = self._get_or_create_bit_signaling_service()
        verification_service = self._get_or_create_verification_service()
        daa = self._get_or_create_daa()
        cpu_mining_service = self._get_or_create_cpu_mining_service()
        vertex_handler = self._get_or_create_vertex_handler()
        vertex_parser = self._get_or_create_vertex_parser()
        poa_block_producer = self._get_or_create_poa_block_producer()
        runner_factory = self._get_or_create_runner_factory()
        vertex_json_serializer = self._get_or_create_vertex_json_serializer()

        if settings.ENABLE_NANO_CONTRACTS:
            tx_storage.nc_catalog = self._get_nc_catalog()

        if self._enable_address_index:
            indexes.enable_address_index(pubsub)

        if self._enable_tokens_index:
            indexes.enable_tokens_index()

        if self._enable_utxo_index:
            indexes.enable_utxo_index()

        if self._enable_nc_indexes:
            indexes.enable_nc_indexes()

        kwargs: dict[str, Any] = {}

        if self._enable_event_queue is not None:
            kwargs['enable_event_queue'] = self._enable_event_queue

        manager = HathorManager(
            reactor,
            settings=settings,
            pubsub=pubsub,
            consensus_algorithm=consensus_algorithm,
            daa=daa,
            peer=peer,
            tx_storage=tx_storage,
            p2p_manager=p2p_manager,
            event_manager=event_manager,
            wallet=wallet,
            rng=self._rng,
            checkpoints=self._checkpoints or settings.CHECKPOINTS,
            capabilities=self._capabilities,
            environment_info=get_environment_info(self._cmdline, str(peer.id)),
            bit_signaling_service=bit_signaling_service,
            verification_service=verification_service,
            cpu_mining_service=cpu_mining_service,
            execution_manager=execution_manager,
            vertex_handler=vertex_handler,
            vertex_parser=vertex_parser,
            poa_block_producer=poa_block_producer,
            runner_factory=runner_factory,
            feature_service=feature_service,
            vertex_json_serializer=vertex_json_serializer,
            **kwargs
        )

        p2p_manager.set_manager(manager)
        if poa_block_producer:
            poa_block_producer.manager = manager

        stratum_factory: Optional[StratumFactory] = None
        if self._enable_stratum_server:
            stratum_factory = self._create_stratum_server(manager)

        self.artifacts = BuildArtifacts(
            peer=peer,
            settings=settings,
            rng=self._rng,
            reactor=reactor,
            manager=manager,
            p2p_manager=p2p_manager,
            pubsub=pubsub,
            consensus=consensus_algorithm,
            tx_storage=tx_storage,
            indexes=indexes,
            wallet=wallet,
            rocksdb_storage=rocksdb_storage,
            stratum_factory=stratum_factory,
            feature_service=feature_service,
            bit_signaling_service=bit_signaling_service,
        )

        return self.artifacts

    def check_if_can_modify(self) -> None:
        if self.artifacts is not None:
            raise ValueError('cannot modify after build() is called')

    def set_event_manager(self, event_manager: EventManager) -> 'Builder':
        self.check_if_can_modify()
        self._event_manager = event_manager
        return self

    def set_feature_service(self, feature_service: FeatureService) -> 'Builder':
        self.check_if_can_modify()
        self._feature_service = feature_service
        return self

    def set_bit_signaling_service(self, bit_signaling_service: BitSignalingService) -> 'Builder':
        self.check_if_can_modify()
        self._bit_signaling_service = bit_signaling_service
        return self

    def set_rng(self, rng: Random) -> 'Builder':
        self.check_if_can_modify()
        self._rng = rng
        return self

    def set_checkpoints(self, checkpoints: list[Checkpoint]) -> 'Builder':
        self.check_if_can_modify()
        self._checkpoints = checkpoints
        return self

    def set_capabilities(self, capabilities: list[str]) -> 'Builder':
        self.check_if_can_modify()
        self._capabilities = capabilities
        return self

    def set_peer(self, peer: PrivatePeer) -> 'Builder':
        self.check_if_can_modify()
        self._peer = peer
        return self

    def _get_or_create_settings(self) -> HathorSettingsType:
        """Return the HathorSettings instance set on this builder, or a new one if not set."""
        if self._settings is None:
            raise ValueError('settings not set')
        return self._settings

    def _get_reactor(self) -> Reactor:
        if self._reactor is not None:
            return self._reactor
        raise ValueError('reactor not set')

    def _get_soft_voided_tx_ids(self) -> set[bytes]:
        if self._soft_voided_tx_ids is not None:
            return self._soft_voided_tx_ids

        settings = self._get_or_create_settings()

        return set(settings.SOFT_VOIDED_TX_IDS)

    def _get_peer(self) -> PrivatePeer:
        if self._peer is not None:
            return self._peer
        raise ValueError('peer not set')

    def _get_or_create_execution_manager(self) -> ExecutionManager:
        if self._execution_manager is None:
            reactor = self._get_reactor()
            self._execution_manager = ExecutionManager(reactor)

        return self._execution_manager

    def _get_or_create_nc_storage_factory(self) -> NCStorageFactory:
        if self._nc_storage_factory is not None:
            return self._nc_storage_factory

        rocksdb_storage = self._get_or_create_rocksdb_storage()
        self._nc_storage_factory = NCRocksDBStorageFactory(rocksdb_storage)
        return self._nc_storage_factory

    def _get_nc_calls_sorter(self) -> NCSorterCallable:
        if self._nc_anti_mev:
            from hathor.nanocontracts.sorter.random_sorter import random_nc_calls_sorter
            return random_nc_calls_sorter
        else:
            from hathor.nanocontracts.sorter.timestamp_sorter import timestamp_nc_calls_sorter
            return timestamp_nc_calls_sorter

    def _get_or_create_nc_log_storage(self) -> NCLogStorage:
        if self._nc_log_storage is not None:
            return self._nc_log_storage

        rocksdb_storage = self._get_or_create_rocksdb_storage()
        self._nc_log_storage = NCLogStorage(
            settings=self._get_or_create_settings(),
            path=rocksdb_storage.path,
            config=self._nc_log_config,
        )
        return self._nc_log_storage

    def _get_or_create_consensus(self) -> ConsensusAlgorithm:
        if self._consensus is None:
            soft_voided_tx_ids = self._get_soft_voided_tx_ids()
            pubsub = self._get_or_create_pubsub()
            nc_storage_factory = self._get_or_create_nc_storage_factory()
            nc_calls_sorter = self._get_nc_calls_sorter()
            self._consensus = ConsensusAlgorithm(
                nc_storage_factory=nc_storage_factory,
                soft_voided_tx_ids=soft_voided_tx_ids,
                pubsub=pubsub,
                settings=self._get_or_create_settings(),
                runner_factory=self._get_or_create_runner_factory(),
                nc_log_storage=self._get_or_create_nc_log_storage(),
                nc_calls_sorter=nc_calls_sorter,
                feature_service=self._get_or_create_feature_service(),
            )

        return self._consensus

    def _get_nc_catalog(self) -> NCBlueprintCatalog:
        from hathor.nanocontracts.catalog import generate_catalog_from_settings
        settings = self._get_or_create_settings()
        return generate_catalog_from_settings(settings)

    def _get_or_create_runner_factory(self) -> RunnerFactory:
        if self._runner_factory is None:
            self._runner_factory = RunnerFactory(
                reactor=self._get_reactor(),
                settings=self._get_or_create_settings(),
                tx_storage=self._get_or_create_tx_storage(),
                nc_storage_factory=self._get_or_create_nc_storage_factory(),
            )
        return self._runner_factory

    def _get_or_create_pubsub(self) -> PubSubManager:
        if self._pubsub is None:
            self._pubsub = PubSubManager(self._get_reactor())
        return self._pubsub

    def _create_stratum_server(self, manager: HathorManager) -> StratumFactory:
        stratum_factory = StratumFactory(manager=manager, reactor=self._get_reactor())
        manager.stratum_factory = stratum_factory
        manager.metrics.stratum_factory = stratum_factory
        return stratum_factory

    def _get_or_create_rocksdb_storage(self) -> RocksDBStorage:
        if self._rocksdb_storage is None:
            self._rocksdb_storage = RocksDBStorage(
                path=self._rocksdb_path,
                cache_capacity=self._rocksdb_cache_capacity,
            ) if self._rocksdb_path else RocksDBStorage.create_temp(self._rocksdb_cache_capacity)
        return self._rocksdb_storage

    def _get_or_create_p2p_manager(self) -> ConnectionsManager:
        if self._p2p_manager:
            return self._p2p_manager

        enable_ssl = True
        reactor = self._get_reactor()
        my_peer = self._get_peer()

        self._p2p_manager = ConnectionsManager(
            settings=self._get_or_create_settings(),
            reactor=reactor,
            my_peer=my_peer,
            pubsub=self._get_or_create_pubsub(),
            ssl=enable_ssl,
            whitelist_only=False,
            rng=self._rng,
            enable_ipv6=self._enable_ipv6,
            disable_ipv4=self._disable_ipv4,
        )
        SyncSupportLevel.add_factories(
            self._get_or_create_settings(),
            self._p2p_manager,
            self._sync_v2_support,
            self._get_or_create_vertex_parser(),
            self._get_or_create_vertex_handler(),
        )
        return self._p2p_manager

    def _get_or_create_indexes_manager(self) -> IndexesManager:
        if self._indexes_manager is None:
            rocksdb_storage = self._get_or_create_rocksdb_storage()
            self._indexes_manager = RocksDBIndexesManager(
                rocksdb_storage,
                settings=self._get_or_create_settings(),
            )
        return self._indexes_manager

    def _get_or_create_tx_storage(self) -> TransactionStorage:
        indexes = self._get_or_create_indexes_manager()
        settings = self._get_or_create_settings()

        if self._tx_storage is not None:
            # If a tx storage is provided, set the indexes manager to it.
            self._tx_storage.indexes = indexes
            return self._tx_storage

        cache_config: CacheConfig | None = None
        if self._tx_storage_cache:
            cache_config = CacheConfig(reactor=self._get_reactor())
            if self._tx_storage_cache_capacity is not None:
                cache_config.capacity = self._tx_storage_cache_capacity

        rocksdb_storage = self._get_or_create_rocksdb_storage()
        nc_storage_factory = self._get_or_create_nc_storage_factory()
        vertex_parser = self._get_or_create_vertex_parser()
        vertex_children_service = RocksDBVertexChildrenService(rocksdb_storage)
        self._tx_storage = TransactionRocksDBStorage(
            rocksdb_storage,
            indexes=indexes,
            settings=settings,
            vertex_parser=vertex_parser,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
            cache_config=cache_config,
        )

        return self._tx_storage

    def _get_or_create_event_storage(self) -> EventStorage:
        if self._event_storage is None:
            rocksdb_storage = self._get_or_create_rocksdb_storage()
            self._event_storage = EventRocksDBStorage(rocksdb_storage)
        return self._event_storage

    def _get_or_create_event_manager(self) -> EventManager:
        if self._event_manager is None:
            peer = self._get_peer()
            settings = self._get_or_create_settings()
            reactor = self._get_reactor()
            storage = self._get_or_create_event_storage()
            factory = EventWebsocketFactory(
                peer_id=str(peer.id),
                settings=settings,
                reactor=reactor,
                event_storage=storage,
            )
            self._event_manager = EventManager(
                reactor=reactor,
                pubsub=self._get_or_create_pubsub(),
                event_storage=storage,
                event_ws_factory=factory,
                execution_manager=self._get_or_create_execution_manager()
            )

        return self._event_manager

    def _get_or_create_feature_service(self) -> FeatureService:
        """Return the FeatureService instance set on this builder, or a new one if not set."""
        if self._feature_service is None:
            settings = self._get_or_create_settings()
            tx_storage = self._get_or_create_tx_storage()
            self._feature_service = FeatureService(settings=settings, tx_storage=tx_storage)

        return self._feature_service

    def _get_or_create_bit_signaling_service(self) -> BitSignalingService:
        if self._bit_signaling_service is None:
            settings = self._get_or_create_settings()
            tx_storage = self._get_or_create_tx_storage()
            feature_service = self._get_or_create_feature_service()
            feature_storage = self._get_or_create_feature_storage()
            self._bit_signaling_service = BitSignalingService(
                settings=settings,
                feature_service=feature_service,
                tx_storage=tx_storage,
                support_features=self._support_features,
                not_support_features=self._not_support_features,
                feature_storage=feature_storage,
            )

        return self._bit_signaling_service

    def _get_or_create_verification_service(self) -> VerificationService:
        if self._verification_service is None:
            settings = self._get_or_create_settings()
            verifiers = self._get_or_create_vertex_verifiers()
            storage = self._get_or_create_tx_storage()
            nc_storage_factory = self._get_or_create_nc_storage_factory()
            self._verification_service = VerificationService(
                settings=settings,
                verifiers=verifiers,
                tx_storage=storage,
                nc_storage_factory=nc_storage_factory,
            )

        return self._verification_service

    def _get_or_create_feature_storage(self) -> FeatureActivationStorage:
        return FeatureActivationStorage(
            settings=self._get_or_create_settings(),
            rocksdb_storage=self._get_or_create_rocksdb_storage()
        )

    def _get_or_create_vertex_verifiers(self) -> VertexVerifiers:
        if self._vertex_verifiers is None:
            reactor = self._get_reactor()
            settings = self._get_or_create_settings()
            feature_service = self._get_or_create_feature_service()
            daa = self._get_or_create_daa()
            tx_storage = self._get_or_create_tx_storage()

            if self._vertex_verifiers_builder:
                self._vertex_verifiers = self._vertex_verifiers_builder(
                    reactor,
                    settings,
                    daa,
                    feature_service,
                    tx_storage
                )
            else:
                self._vertex_verifiers = VertexVerifiers.create_defaults(
                    reactor=reactor,
                    settings=settings,
                    daa=daa,
                    feature_service=feature_service,
                    tx_storage=tx_storage,
                )

        return self._vertex_verifiers

    def _get_or_create_daa(self) -> DifficultyAdjustmentAlgorithm:
        if self._daa is None:
            settings = self._get_or_create_settings()
            self._daa = DifficultyAdjustmentAlgorithm(settings=settings)

        return self._daa

    def _get_or_create_cpu_mining_service(self) -> CpuMiningService:
        if self._cpu_mining_service is None:
            self._cpu_mining_service = CpuMiningService()

        return self._cpu_mining_service

    def _get_or_create_vertex_handler(self) -> VertexHandler:
        if self._vertex_handler is None:
            self._vertex_handler = VertexHandler(
                reactor=self._get_reactor(),
                settings=self._get_or_create_settings(),
                tx_storage=self._get_or_create_tx_storage(),
                verification_service=self._get_or_create_verification_service(),
                consensus=self._get_or_create_consensus(),
                feature_service=self._get_or_create_feature_service(),
                execution_manager=self._get_or_create_execution_manager(),
                pubsub=self._get_or_create_pubsub(),
                wallet=self._get_or_create_wallet(),
            )

        return self._vertex_handler

    def _get_or_create_vertex_parser(self) -> VertexParser:
        if self._vertex_parser is None:
            self._vertex_parser = VertexParser(
                settings=self._get_or_create_settings()
            )

        return self._vertex_parser

    def _get_or_create_poa_block_producer(self) -> PoaBlockProducer | None:
        if not self._poa_signer:
            return None

        if self._poa_block_producer is None:
            self._poa_block_producer = PoaBlockProducer(
                settings=self._get_or_create_settings(),
                reactor=self._get_reactor(),
                poa_signer=self._poa_signer,
            )

        return self._poa_block_producer

    def _get_or_create_vertex_json_serializer(self) -> VertexJsonSerializer:
        if self._vertex_json_serializer is None:
            tx_storage = self._get_or_create_tx_storage()
            nc_log_storage = self._get_or_create_nc_log_storage()
            self._vertex_json_serializer = VertexJsonSerializer(
                storage=tx_storage,
                nc_log_storage=nc_log_storage,
            )

        return self._vertex_json_serializer

    def set_rocksdb_path(self, path: str | tempfile.TemporaryDirectory) -> 'Builder':
        if self._tx_storage:
            raise ValueError('cannot set rocksdb path after tx storage is set')
        self.check_if_can_modify()
        self._rocksdb_path = path
        return self

    def set_rocksdb_cache_capacity(self, cache_capacity: int) -> 'Builder':
        if self._tx_storage:
            raise ValueError('cannot set rocksdb cache capacity after tx storage is set')
        self.check_if_can_modify()
        self._rocksdb_cache_capacity = cache_capacity
        return self

    def use_tx_storage_cache(self, capacity: Optional[int] = None) -> 'Builder':
        if self._tx_storage:
            raise ValueError('cannot set tx storage cache capacity after tx storage is set')
        self.check_if_can_modify()
        self._tx_storage_cache = True
        self._tx_storage_cache_capacity = capacity
        return self

    def _get_or_create_wallet(self) -> Optional[BaseWallet]:
        if self._wallet is not None:
            return self._wallet

        if self._wallet_directory is None:
            return None
        self._wallet = Wallet(directory=self._wallet_directory, settings=self._get_or_create_settings())
        if self._wallet_unlock is not None:
            self._wallet.unlock(self._wallet_unlock)
        return self._wallet

    def set_wallet(self, wallet: BaseWallet) -> 'Builder':
        self.check_if_can_modify()
        self._wallet = wallet
        return self

    def enable_keypair_wallet(self, directory: str, *, unlock: Optional[bytes] = None) -> 'Builder':
        self.check_if_can_modify()
        self._wallet_directory = directory
        self._wallet_unlock = unlock
        return self

    def enable_stratum_server(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_stratum_server = True
        return self

    def enable_address_index(self) -> 'Builder':
        if self._tx_storage or self._indexes_manager:
            raise ValueError('cannot enable index after tx storage or indexes manager is set')
        self.check_if_can_modify()
        self._enable_address_index = True
        return self

    def enable_tokens_index(self) -> 'Builder':
        if self._tx_storage or self._indexes_manager:
            raise ValueError('cannot enable index after tx storage or indexes manager is set')
        self.check_if_can_modify()
        self._enable_tokens_index = True
        return self

    def enable_utxo_index(self) -> 'Builder':
        if self._tx_storage or self._indexes_manager:
            raise ValueError('cannot enable index after tx storage or indexes manager is set')
        self.check_if_can_modify()
        self._enable_utxo_index = True
        return self

    def enable_nc_indexes(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_nc_indexes = True
        return self

    def enable_wallet_index(self) -> 'Builder':
        if self._tx_storage or self._indexes_manager:
            raise ValueError('cannot enable index after tx storage or indexes manager is set')
        self.check_if_can_modify()
        self.enable_address_index()
        self.enable_tokens_index()
        return self

    def enable_event_queue(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_event_queue = True
        return self

    def set_tx_storage(self, tx_storage: TransactionStorage) -> 'Builder':
        self.check_if_can_modify()
        self._tx_storage = tx_storage
        assert isinstance(tx_storage, TransactionRocksDBStorage)
        self._rocksdb_storage = tx_storage._rocksdb_storage
        return self

    def set_event_storage(self, event_storage: EventStorage) -> 'Builder':
        self.check_if_can_modify()
        self._event_storage = event_storage
        return self

    def set_verification_service(self, verification_service: VerificationService) -> 'Builder':
        self.check_if_can_modify()
        self._verification_service = verification_service
        return self

    def set_vertex_verifiers(self, vertex_verifiers: VertexVerifiers) -> 'Builder':
        self.check_if_can_modify()
        self._vertex_verifiers = vertex_verifiers
        return self

    def set_vertex_verifiers_builder(self, builder: _VertexVerifiersBuilder) -> 'Builder':
        self.check_if_can_modify()
        self._vertex_verifiers_builder = builder
        return self

    def set_daa(self, daa: DifficultyAdjustmentAlgorithm) -> 'Builder':
        self.check_if_can_modify()
        self._daa = daa
        return self

    def set_cpu_mining_service(self, cpu_mining_service: CpuMiningService) -> 'Builder':
        self.check_if_can_modify()
        self._cpu_mining_service = cpu_mining_service
        return self

    def set_reactor(self, reactor: Reactor) -> 'Builder':
        self.check_if_can_modify()
        self._reactor = reactor
        return self

    def set_pubsub(self, pubsub: PubSubManager) -> 'Builder':
        self.check_if_can_modify()
        self._pubsub = pubsub
        return self

    def set_sync_v2_support(self, support_level: SyncSupportLevel) -> 'Builder':
        self.check_if_can_modify()
        self._sync_v2_support = support_level
        return self

    def enable_sync_v2(self) -> 'Builder':
        self.check_if_can_modify()
        self._sync_v2_support = SyncSupportLevel.ENABLED
        return self

    def disable_sync_v2(self) -> 'Builder':
        self.check_if_can_modify()
        self._sync_v2_support = SyncSupportLevel.DISABLED
        return self

    def enable_ipv6(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_ipv6 = True
        return self

    def disable_ipv4(self) -> 'Builder':
        self.check_if_can_modify()
        self._disable_ipv4 = True
        return self

    def enable_nc_anti_mev(self) -> 'Builder':
        self.check_if_can_modify()
        self._nc_anti_mev = True
        return self

    def disable_nc_anti_mev(self) -> 'Builder':
        self.check_if_can_modify()
        self._nc_anti_mev = False
        return self

    def set_soft_voided_tx_ids(self, soft_voided_tx_ids: set[bytes]) -> 'Builder':
        self.check_if_can_modify()
        self._soft_voided_tx_ids = soft_voided_tx_ids
        return self

    def set_features(
        self,
        *,
        support_features: Optional[set[Feature]],
        not_support_features: Optional[set[Feature]]
    ) -> 'Builder':
        self.check_if_can_modify()
        self._support_features = support_features or set()
        self._not_support_features = not_support_features or set()
        return self

    def set_settings(self, settings: HathorSettingsType) -> 'Builder':
        self.check_if_can_modify()
        self._settings = settings
        return self

    def set_poa_signer(self, signer: PoaSigner) -> 'Builder':
        self.check_if_can_modify()
        self._poa_signer = signer
        return self

    def set_nc_log_config(self, config: NCLogConfig) -> 'Builder':
        self.check_if_can_modify()
        self._nc_log_config = config
        return self
