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

from enum import Enum
from typing import Any, Dict, List, NamedTuple, Optional, Set

from structlog import get_logger

from hathor.checkpoint import Checkpoint
from hathor.conf import HathorSettings
from hathor.conf.settings import HathorSettings as HathorSettingsType
from hathor.consensus import ConsensusAlgorithm
from hathor.event import EventManager
from hathor.event.storage import EventMemoryStorage, EventRocksDBStorage, EventStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.indexes import IndexesManager
from hathor.manager import HathorManager
from hathor.p2p.peer_id import PeerId
from hathor.pubsub import PubSubManager
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import TransactionMemoryStorage, TransactionRocksDBStorage, TransactionStorage
from hathor.util import Random, Reactor, get_environment_info
from hathor.wallet import BaseWallet, Wallet

logger = get_logger()


class StorageType(Enum):
    MEMORY = 'memory'
    ROCKSDB = 'rocksdb'


class BuildArtifacts(NamedTuple):
    """Artifacts created by a builder."""
    peer_id: PeerId
    settings: HathorSettingsType
    rng: Random
    reactor: Reactor
    manager: HathorManager
    pubsub: PubSubManager
    consensus: ConsensusAlgorithm
    tx_storage: TransactionStorage
    indexes: Optional[IndexesManager]
    wallet: Optional[BaseWallet]
    rocksdb_storage: Optional[RocksDBStorage]


class Builder:
    """Builder builds the core objects to run a full node.

    Example:

        builder = Builder()
        builder.use_memory()
        artifacts = builder.build()
    """
    def __init__(self) -> None:
        self.log = logger.new()
        self.artifacts: Optional[BuildArtifacts] = None

        self._settings: HathorSettingsType = HathorSettings()
        self._rng: Random = Random()
        self._checkpoints: Optional[List[Checkpoint]] = None
        self._capabilities: Optional[List[str]] = None

        self._peer_id: Optional[PeerId] = None
        self._network: Optional[str] = None
        self._cmdline: str = ''

        self._storage_type: StorageType = StorageType.MEMORY
        self._force_memory_index: bool = False

        self._event_manager: Optional[EventManager] = None
        self._event_ws_factory: Optional[EventWebsocketFactory] = None
        self._enable_event_queue: Optional[bool] = None

        self._rocksdb_path: Optional[str] = None
        self._rocksdb_storage: Optional[RocksDBStorage] = None
        self._rocksdb_cache_capacity: Optional[int] = None
        self._rocksdb_with_index: Optional[bool] = None

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

        self._enable_sync_v1: Optional[bool] = None
        self._enable_sync_v2: Optional[bool] = None

        self._stratum_port: Optional[int] = None

        self._full_verification: Optional[bool] = None

        self._soft_voided_tx_ids: Optional[Set[bytes]] = None

    def build(self) -> BuildArtifacts:
        if self.artifacts is not None:
            raise ValueError('cannot call build twice')

        settings = self._get_settings()
        reactor = self._get_reactor()
        pubsub = self._get_or_create_pubsub()

        peer_id = self._get_peer_id()

        soft_voided_tx_ids = self._get_soft_voided_tx_ids()
        consensus_algorithm = ConsensusAlgorithm(soft_voided_tx_ids, pubsub)

        wallet = self._get_or_create_wallet()
        event_manager = self._get_or_create_event_manager()
        tx_storage = self._get_or_create_tx_storage()
        indexes = tx_storage.indexes
        assert indexes is not None

        if self._enable_address_index:
            indexes.enable_address_index(pubsub)

        if self._enable_tokens_index:
            indexes.enable_tokens_index()

        if self._enable_utxo_index:
            indexes.enable_utxo_index()

        kwargs: Dict[str, Any] = {}

        if self._enable_sync_v1 is not None:
            kwargs['enable_sync_v1'] = self._enable_sync_v1

        if self._enable_sync_v2 is not None:
            kwargs['enable_sync_v2'] = self._enable_sync_v2

        if self._stratum_port is not None:
            kwargs['stratum_port'] = self._stratum_port

        if self._network is None:
            raise TypeError('you must set a network')

        if self._full_verification is not None:
            kwargs['full_verification'] = self._full_verification

        if self._enable_event_queue is not None:
            kwargs['enable_event_queue'] = self._enable_event_queue

        manager = HathorManager(
            reactor,
            pubsub=pubsub,
            consensus_algorithm=consensus_algorithm,
            peer_id=peer_id,
            tx_storage=tx_storage,
            event_manager=event_manager,
            network=self._network,
            wallet=wallet,
            rng=self._rng,
            checkpoints=self._checkpoints,
            capabilities=self._capabilities,
            environment_info=get_environment_info(self._cmdline, peer_id.id),
            **kwargs
        )

        self.artifacts = BuildArtifacts(
            peer_id=peer_id,
            settings=settings,
            rng=self._rng,
            reactor=reactor,
            manager=manager,
            pubsub=pubsub,
            consensus=consensus_algorithm,
            tx_storage=tx_storage,
            indexes=indexes,
            wallet=wallet,
            rocksdb_storage=self._rocksdb_storage,
        )

        return self.artifacts

    def check_if_can_modify(self) -> None:
        if self.artifacts is not None:
            raise ValueError('cannot modify after build() is called')

    def set_event_manager(self, event_manager: EventManager) -> 'Builder':
        self.check_if_can_modify()
        self._event_manager = event_manager
        return self

    def set_rng(self, rng: Random) -> 'Builder':
        self.check_if_can_modify()
        self._rng = rng
        return self

    def set_checkpoints(self, checkpoints: List[Checkpoint]) -> 'Builder':
        self.check_if_can_modify()
        self._checkpoints = checkpoints
        return self

    def set_capabilities(self, capabilities: List[str]) -> 'Builder':
        self.check_if_can_modify()
        self._capabilities = capabilities
        return self

    def set_peer_id(self, peer_id: PeerId) -> 'Builder':
        self.check_if_can_modify()
        self._peer_id = peer_id
        return self

    def _get_settings(self) -> HathorSettingsType:
        return self._settings

    def _get_reactor(self) -> Reactor:
        if self._reactor is not None:
            return self._reactor
        raise ValueError('reactor not set')

    def _get_soft_voided_tx_ids(self) -> Set[bytes]:
        if self._soft_voided_tx_ids is not None:
            return self._soft_voided_tx_ids

        settings = self._get_settings()

        return set(settings.SOFT_VOIDED_TX_IDS)

    def _get_peer_id(self) -> PeerId:
        if self._peer_id is not None:
            return self._peer_id
        raise ValueError('peer_id not set')

    def _get_or_create_pubsub(self) -> PubSubManager:
        if self._pubsub is None:
            self._pubsub = PubSubManager(self._get_reactor())
        return self._pubsub

    def _get_or_create_rocksdb_storage(self) -> RocksDBStorage:
        assert self._rocksdb_path is not None

        if self._rocksdb_storage is not None:
            return self._rocksdb_storage

        kwargs = {}
        if self._rocksdb_cache_capacity is not None:
            kwargs = dict(cache_capacity=self._rocksdb_cache_capacity)

        self._rocksdb_storage = RocksDBStorage(
            path=self._rocksdb_path,
            **kwargs
        )

        return self._rocksdb_storage

    def _get_or_create_tx_storage(self) -> TransactionStorage:
        if self._tx_storage is not None:
            return self._tx_storage

        if self._storage_type == StorageType.MEMORY:
            return TransactionMemoryStorage()

        if self._storage_type == StorageType.ROCKSDB:
            rocksdb_storage = self._get_or_create_rocksdb_storage()
            use_memory_index = self._force_memory_index

            kwargs = {}
            if self._rocksdb_with_index is not None:
                kwargs = dict(with_index=self._rocksdb_with_index)

            return TransactionRocksDBStorage(
                rocksdb_storage,
                use_memory_indexes=use_memory_index,
                **kwargs
            )

        raise NotImplementedError

    def _get_or_create_event_storage(self) -> EventStorage:
        if self._event_storage is not None:
            pass
        elif self._storage_type == StorageType.MEMORY:
            self._event_storage = EventMemoryStorage()
        elif self._storage_type == StorageType.ROCKSDB:
            rocksdb_storage = self._get_or_create_rocksdb_storage()
            self._event_storage = EventRocksDBStorage(rocksdb_storage)
        else:
            raise NotImplementedError

        return self._event_storage

    def _get_or_create_event_manager(self) -> EventManager:
        if self._event_manager is None:
            self._event_manager = EventManager(
                reactor=self._get_reactor(),
                pubsub=self._get_or_create_pubsub(),
                event_storage=self._get_or_create_event_storage(),
                event_ws_factory=self._event_ws_factory
            )

        return self._event_manager

    def use_memory(self) -> 'Builder':
        self.check_if_can_modify()
        self._storage_type = StorageType.MEMORY
        return self

    def use_rocksdb(
        self,
        path: str,
        with_index: Optional[bool] = None,
        cache_capacity: Optional[int] = None
    ) -> 'Builder':
        self.check_if_can_modify()
        self._storage_type = StorageType.ROCKSDB
        self._rocksdb_path = path
        self._rocksdb_with_index = with_index
        self._rocksdb_cache_capacity = cache_capacity
        return self

    def force_memory_index(self) -> 'Builder':
        self.check_if_can_modify()
        self._force_memory_index = True
        return self

    def _get_or_create_wallet(self) -> Optional[BaseWallet]:
        if self._wallet is not None:
            assert self._wallet_directory is None
            assert self._wallet_unlock is None
            return self._wallet

        if self._wallet_directory is None:
            return None
        wallet = Wallet(directory=self._wallet_directory)
        if self._wallet_unlock is not None:
            wallet.unlock(self._wallet_unlock)
        return wallet

    def set_wallet(self, wallet: BaseWallet) -> 'Builder':
        self.check_if_can_modify()
        self._wallet = wallet
        return self

    def enable_keypair_wallet(self, directory: str, *, unlock: Optional[bytes] = None) -> 'Builder':
        self.check_if_can_modify()
        self._wallet_directory = directory
        self._wallet_unlock = unlock
        return self

    def enable_stratum_server(self, port: int) -> 'Builder':
        self.check_if_can_modify()
        self._stratum_port = port
        return self

    def enable_address_index(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_address_index = True
        return self

    def enable_tokens_index(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_tokens_index = True
        return self

    def enable_utxo_index(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_utxo_index = True
        return self

    def enable_wallet_index(self) -> 'Builder':
        self.check_if_can_modify()
        self.enable_address_index()
        self.enable_tokens_index()
        return self

    def enable_event_manager(self, *, event_ws_factory: EventWebsocketFactory) -> 'Builder':
        self.check_if_can_modify()
        self._enable_event_queue = True
        self._event_ws_factory = event_ws_factory
        return self

    def set_tx_storage(self, tx_storage: TransactionStorage) -> 'Builder':
        self.check_if_can_modify()
        self._tx_storage = tx_storage
        return self

    def set_event_storage(self, event_storage: EventStorage) -> 'Builder':
        self.check_if_can_modify()
        self._event_storage = event_storage
        return self

    def set_reactor(self, reactor: Reactor) -> 'Builder':
        self.check_if_can_modify()
        self._reactor = reactor
        return self

    def set_pubsub(self, pubsub: PubSubManager) -> 'Builder':
        self.check_if_can_modify()
        self._pubsub = pubsub
        return self

    def set_network(self, network: str) -> 'Builder':
        self.check_if_can_modify()
        self._network = network
        return self

    def set_enable_sync_v1(self, enable_sync_v1: bool) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v1 = enable_sync_v1
        return self

    def set_enable_sync_v2(self, enable_sync_v2: bool) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v2 = enable_sync_v2
        return self

    def enable_sync_v1(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v1 = True
        return self

    def disable_sync_v1(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v1 = False
        return self

    def enable_sync_v2(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v2 = True
        return self

    def disable_sync_v2(self) -> 'Builder':
        self.check_if_can_modify()
        self._enable_sync_v2 = False
        return self

    def set_full_verification(self, full_verification: bool) -> 'Builder':
        self.check_if_can_modify()
        self._full_verification = full_verification
        return self

    def set_soft_voided_tx_ids(self, soft_voided_tx_ids: Set[bytes]) -> 'Builder':
        self.check_if_can_modify()
        self._soft_voided_tx_ids = soft_voided_tx_ids
        return self
