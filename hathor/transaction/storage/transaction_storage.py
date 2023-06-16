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

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod, abstractproperty
from collections import deque
from contextlib import AbstractContextManager
from threading import Lock
from typing import TYPE_CHECKING, Any, Iterator, NamedTuple, Optional, cast
from weakref import WeakValueDictionary

from intervaltree.interval import Interval
from structlog import get_logger

from hathor.execution_manager import ExecutionManager
from hathor.indexes import IndexesManager
from hathor.indexes.height_index import HeightInfo
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import PubSubManager
from hathor.transaction.base_transaction import BaseTransaction, TxOutput, Vertex
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import (
    TokenCreationTransactionDoesNotExist,
    TransactionDoesNotExist,
    TransactionIsNotABlock,
    TransactionNotInAllowedScopeError,
)
from hathor.transaction.storage.migrations import (
    BaseMigration,
    MigrationState,
    add_closest_ancestor_block,
    change_score_acc_weight_metadata,
    include_funds_for_first_block,
    migrate_vertex_children,
    nc_storage_compat2,
)
from hathor.transaction.storage.tx_allow_scope import TxAllowScope, tx_allow_context
from hathor.transaction.transaction import Transaction
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.transaction.vertex_children import VertexChildrenService
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts import OnChainBlueprint
    from hathor.nanocontracts.blueprint import Blueprint
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.storage import NCBlockStorage, NCContractStorage, NCStorageFactory
    from hathor.nanocontracts.types import BlueprintId, ContractId
    from hathor.transaction.token_creation_tx import TokenCreationTransaction

cpu = get_cpu_profiler()

# these are the timestamp values to be used when resetting them, 1 is used for the node instead of 0, so it can be
# greater, that way if both are reset (which also happens on a database that never run this implementation before) we
# guarantee that indexes will be initialized (because they would be "older" than the node timestamp).
NULL_INDEX_LAST_STARTED_AT = 0
NULL_LAST_STARTED_AT = 1
INDEX_ATTR_PREFIX = 'index_'


class AllTipsCache(NamedTuple):
    timestamp: int
    tips: set[Interval]
    merkle_tree: bytes
    hashes: list[bytes]


class TransactionStorage(ABC):
    """Legacy sync interface, please copy @deprecated decorator when implementing methods."""

    pubsub: Optional[PubSubManager]
    indexes: Optional[IndexesManager]
    _latest_n_height_tips: list[HeightInfo]
    nc_catalog: Optional['NCBlueprintCatalog'] = None

    log = get_logger()

    # Key storage attribute to save if the network stored is the expected network
    _network_attribute: str = 'network'

    # Key storage attribute to save if the manager is running
    _manager_running_attribute: str = 'manager_running'

    # Key storage attribute to save if the full node crashed
    _full_node_crashed_attribute: str = 'full_node_crashed'

    # Ket storage attribute to save the last time the node started
    _last_start_attribute: str = 'last_start'

    # history of migrations that have to be applied in the order defined here
    _migration_factories: list[type[BaseMigration]] = [
        change_score_acc_weight_metadata.Migration,
        add_closest_ancestor_block.Migration,
        include_funds_for_first_block.Migration,
        nc_storage_compat2.Migration,
        migrate_vertex_children.Migration,
    ]

    _migrations: list[BaseMigration]

    def __init__(
        self,
        *,
        settings: HathorSettings,
        nc_storage_factory: NCStorageFactory,
        vertex_children_service: VertexChildrenService,
    ) -> None:
        self._settings = settings
        self._nc_storage_factory = nc_storage_factory
        self.vertex_children = vertex_children_service
        # Weakref is used to guarantee that there is only one instance of each transaction in memory.
        self._tx_weakref: WeakValueDictionary[bytes, BaseTransaction] = WeakValueDictionary()
        self._tx_weakref_disabled: bool = False

        # This lock is needed everytime a storage is getting a tx from the weakref and,
        # in the case the tx is not there, it creates a new object to save there.
        # We were having some concurrent access and two different objects were being saved
        # in the weakref, what is an error (https://github.com/HathorNetwork/hathor-core/issues/70)
        # With this lock we guarantee there isn't going to be any problem with concurrent access
        self._weakref_lock_per_hash: WeakValueDictionary[bytes, Lock] = WeakValueDictionary()

        # This is a global lock used to prevent concurrent access when getting the tx lock in the dict above
        self._weakref_lock: Lock = Lock()

        # Flag to allow/disallow partially validated vertices.
        self._allow_scope: TxAllowScope = TxAllowScope.VALID

        # Cache for the best block tips
        # This cache is updated in the consensus algorithm.
        self._best_block_tips_cache: Optional[list[bytes]] = None

        # If should create lock when getting a transaction
        self._should_lock = False

        # Provide local logger
        self.log = self.log.new()

        # Cache for the latest timestamp of all tips with merkle tree precalculated to be used on the sync algorithm
        # This cache is invalidated every time a new tx or block is added to the cache and
        # self._all_tips_cache.timestamp is always self.latest_timestamp
        self._all_tips_cache: Optional[AllTipsCache] = None

        # Initialize cache for genesis transactions.
        self._genesis_cache: dict[bytes, BaseTransaction] = {}

        # Internal toggle to choose when to select topological DFS iterator, used only on some tests
        self._always_use_topological_dfs = False

        self._saving_genesis = False

        # Migrations instances
        self._migrations = [cls() for cls in self._migration_factories]

        # XXX: sanity check
        migration_names = set()
        for migration in self._migrations:
            migration_name = migration.get_db_name()
            if migration_name in migration_names:
                raise ValueError(f'Duplicate migration name "{migration_name}"')
            migration_names.add(migration_name)

    def set_allow_scope(self, allow_scope: TxAllowScope) -> None:
        """Set the allow scope for the current storage.

        This method should not normally be used directly, use one of the `allow_*_scope` methods instead."""
        self._allow_scope = allow_scope

    def get_allow_scope(self) -> TxAllowScope:
        """Get the current allow scope."""
        return self._allow_scope

    @abstractmethod
    def reset_indexes(self) -> None:
        """Reset all the indexes, making sure that no persisted value is reused."""
        raise NotImplementedError

    @abstractmethod
    def is_empty(self) -> bool:
        """True when only genesis is present, useful for checking for a fresh database."""
        raise NotImplementedError

    def update_best_block_tips_cache(self, tips_cache: Optional[list[bytes]]) -> None:
        # XXX: check that the cache update is working properly, only used in unittests
        # XXX: this might not actually hold true in some cases, commenting out while we figure it out
        # if settings.SLOW_ASSERTS:
        #     calculated_tips = self.get_best_block_tips(skip_cache=True)
        #     self.log.debug('cached best block tips must match calculated',
        #                    calculated=[i.hex() for i in calculated_tips],
        #                    cached=[i.hex() for i in tips_cache])
        #     assert set(tips_cache) == set(calculated_tips)
        self._best_block_tips_cache = tips_cache

    def pre_init(self) -> None:
        """Storages can implement this to run code before transaction loading starts"""
        self._check_and_set_network()
        self._check_and_apply_migrations()

    @abstractmethod
    def get_migration_state(self, migration_name: str) -> MigrationState:
        raise NotImplementedError

    @abstractmethod
    def set_migration_state(self, migration_name: str, state: MigrationState) -> None:
        raise NotImplementedError

    def _check_and_apply_migrations(self) -> None:
        """Check which migrations have not been run yet and apply them in order."""
        from hathor.transaction.storage.exceptions import OutOfOrderMigrationError, PartialMigrationError
        db_is_empty = self.is_empty()
        self.log.debug('step through all migrations', count=len(self._migrations))
        migrations_to_run = []
        # XXX: this is used to ensure migrations don't advance out of order
        previous_migration_state = MigrationState.COMPLETED
        for migration in self._migrations:
            migration_name = migration.get_db_name()
            self.log.debug('step migration', migration=migration_name)

            # short-cut to avoid running migrations on empty database
            if migration.skip_empty_db() and db_is_empty:
                self.log.debug('migration is new, but does not need to run on an empty database',
                               migration=migration_name)
                self.set_migration_state(migration_name, MigrationState.COMPLETED)
                continue

            # get the migration state to decide whether to run, skip or error
            migration_state = self.get_migration_state(migration_name)

            if migration_state > previous_migration_state:
                raise OutOfOrderMigrationError(f'{migration_name} ran after a migration that wasn\'t advanced')
            previous_migration_state = migration_state

            should_run_migration: bool
            if migration_state == MigrationState.NOT_STARTED:
                self.log.debug('migration is new, will run', migration=migration_name)
                should_run_migration = True
            elif migration_state == MigrationState.STARTED:
                self.log.warn('this migration was started before, but it is not marked as COMPLETED or ERROR, '
                              'it will run again but might fail', migration=migration_name)
                should_run_migration = True
            elif migration_state == MigrationState.COMPLETED:
                self.log.debug('migration is already complete', migration=migration_name)
                should_run_migration = False
            elif migration_state == MigrationState.ERROR:
                self.log.error('this migration was run before but resulted in an error, the database will need to be '
                               'either manually fixed or discarded', migration=migration_name)
                raise PartialMigrationError(f'Migration error state previously: {migration_name}')
            else:
                raise ValueError(f'Unexcepted migration state: {migration_state!r}')

            # run if needed, updating the state along the way
            if should_run_migration:
                migrations_to_run.append(migration)
        self.log.debug('stepped through all migrations')
        if migrations_to_run:
            self.log.info('there are migrations that need to be applied')
        migrations_to_run_count = len(migrations_to_run)
        for i, migration in enumerate(migrations_to_run):
            migration_name = migration.get_db_name()
            self.log.info(f'running migration {i+1} out of {migrations_to_run_count}', migration=migration_name)
            self.set_migration_state(migration_name, MigrationState.STARTED)
            try:
                migration.run(self)
            # XXX: we catch "any" exception because just we want to mark the state as "ERROR"
            except Exception as exc:
                self.set_migration_state(migration_name, MigrationState.ERROR)
                raise PartialMigrationError(f'Migration error state: {migration_name}') from exc
            else:
                self.set_migration_state(migration_name, MigrationState.COMPLETED)
        if migrations_to_run:
            self.log.info('all migrations have been applied')

    def _check_and_set_network(self) -> None:
        """Check the network name is as expected and try to set it when none is present"""
        from hathor.transaction.storage.exceptions import WrongNetworkError

        network = self._settings.NETWORK_NAME
        stored_network = self.get_network()

        if stored_network is None:
            # no network is set, let's try to infer it
            self._checked_set_network(network)
        elif stored_network != network:
            # the stored network does not match, something is wrong
            raise WrongNetworkError(f'Databases created on {stored_network}, expected {network}')
        else:
            # the network is what is expected, nothing to do here
            pass

    def _checked_set_network(self, network: str) -> None:
        """Tries to set the network name on storage, while checking if we can safely do so."""
        from hathor.transaction.storage.exceptions import WrongNetworkError

        if self.is_empty():
            # we're fresh out of a new database, let's just make sure we don't have the wrong genesis
            for tx in self.get_all_transactions():
                # XXX: maybe this can happen if you start a fresh database on one network and the genesis is saved
                #      somehow (is this even possible?) and you then start on a different network, hopefully this
                #      can be safely removed in a few releases
                if not tx.is_genesis:
                    raise WrongNetworkError(f'Transaction {tx.hash_hex} is not from {network}')
            self.set_network(network)
        else:
            # XXX: the database IS NOT empty, what do we do?
            #      - for the sake of compatibility we will accept this on the mainnet, and set it as mainnet,
            #        this is mostly so everyone running on the mainnet has a no-interaction auto-migration
            #      - for the sake of cleaning up the mess of foxtrot->golf testnet migration, we'll refuse to use
            #        the database when it is not the mainnet
            #      - in a few releases we can be confident that everyone running the network has made a smooth
            #        upgrade and we should be able to remove these workarounds and refuse older databases, and
            #        instead indiviudally assist (like suggesting a snapshot or fresh start) to anyone that is
            #        unable to use a very old database
            if network == 'mainnet':
                self.set_network(network)
            else:
                raise WrongNetworkError(f'This database is not suitable to be used on {network}')

    def get_best_block(self) -> Block:
        """The block with highest score or one of the blocks with highest scores. Can be used for mining."""
        assert self.indexes is not None
        block_hash = self.indexes.height.get_tip()
        block = self.get_transaction(block_hash)
        assert isinstance(block, Block)
        assert block.get_metadata().validation.is_fully_connected()
        return block

    def _save_or_verify_genesis(self) -> None:
        """Save all genesis in the storage."""
        self._saving_genesis = True
        genesis_txs = [
            self._construct_genesis_block(),
            self._construct_genesis_tx1(),
            self._construct_genesis_tx2(),
        ]

        for tx in genesis_txs:
            tx.init_static_metadata_from_storage(self._settings, self)
            try:
                tx2 = self.get_transaction(tx.hash)
                assert tx == tx2
            except TransactionDoesNotExist:
                self.save_transaction(tx)
                self.add_to_indexes(tx)
                tx2 = tx
            self._genesis_cache[tx2.hash] = tx2
        self._saving_genesis = False

    def _save_to_weakref(self, tx: BaseTransaction) -> None:
        """ Save transaction to weakref.
        """
        if self._tx_weakref_disabled:
            return
        tx2 = self._tx_weakref.get(tx.hash, None)
        if tx2 is None:
            self._tx_weakref[tx.hash] = tx
        else:
            assert tx is tx2, 'There are two instances of the same transaction in memory ({})'.format(tx.hash_hex)

    def _remove_from_weakref(self, tx: BaseTransaction) -> None:
        """Remove transaction from weakref.
        """
        if self._tx_weakref_disabled:
            return
        self._tx_weakref.pop(tx.hash, None)

    def get_transaction_from_weakref(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        """ Get a transaction from weakref if it exists. Otherwise, returns None.
        """
        if self._tx_weakref_disabled:
            return None
        return self._tx_weakref.get(hash_bytes, None)

    # TODO: check if the method bellow is currently needed
    def allow_only_valid_context(self) -> AbstractContextManager[None]:
        """This method is used to temporarily reset the storage back to only allow valid transactions.

        The implementation will OVERRIDE the current scope to allowing only valid transactions on the observed
        storage.
        """
        return tx_allow_context(self, allow_scope=TxAllowScope.VALID)

    def allow_partially_validated_context(self) -> AbstractContextManager[None]:
        """This method is used to temporarily make the storage allow partially validated transactions.

        The implementation will INCLUDE allowing partially valid transactions to the current allow scope.
        """
        new_allow_scope = self.get_allow_scope() | TxAllowScope.PARTIAL
        return tx_allow_context(self, allow_scope=new_allow_scope)

    def allow_invalid_context(self) -> AbstractContextManager[None]:
        """This method is used to temporarily make the storage allow invalid transactions.

        The implementation will INCLUDE allowing invalid transactions to the current allow scope.
        """
        new_allow_scope = self.get_allow_scope() | TxAllowScope.INVALID
        return tx_allow_context(self, allow_scope=new_allow_scope)

    def is_only_valid_allowed(self) -> bool:
        """Whether only valid transactions are allowed to be returned/accepted by the storage, the default state."""
        return self.get_allow_scope() == TxAllowScope.VALID

    def is_partially_validated_allowed(self) -> bool:
        """Whether partially validated transactions are allowed to be returned/accepted by the storage."""
        return TxAllowScope.PARTIAL in self.get_allow_scope()

    def is_invalid_allowed(self) -> bool:
        """Whether invalid transactions are allowed to be returned/accepted by the storage."""
        return TxAllowScope.INVALID in self.get_allow_scope()

    def _enable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = False

    def _disable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = True

    @abstractmethod
    def save_transaction(self: 'TransactionStorage', tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        # XXX: although this method is abstract (because a subclass must implement it) the implementer
        #      should call the base implementation for correctly interacting with the index
        """Saves the tx.

        :param tx: Transaction to save
        :param only_metadata: Don't save the transaction, only the metadata of this transaction
        """
        meta = tx.get_metadata()
        self.pre_save_validation(tx, meta)
        self._save_static_metadata(tx)

    @abstractmethod
    def _save_static_metadata(self, vertex: BaseTransaction) -> None:
        """Save a vertex's static metadata to this storage."""
        raise NotImplementedError

    def pre_save_validation(self, tx: BaseTransaction, tx_meta: TransactionMetadata) -> None:
        """ Must be run before every save, will raise AssertionError or TransactionNotInAllowedScopeError

        A failure means there is a bug in the code that allowed the condition to reach the "save" code. This is a last
        second measure to prevent persisting a bad transaction/metadata.

        This method receives the transaction AND the metadata in order to avoid calling ".get_metadata()" which could
        potentially create a fresh metadata.
        """
        assert tx_meta.hash is not None
        assert tx.hash == tx_meta.hash, f'{tx.hash.hex()} != {tx_meta.hash.hex()}'
        self._validate_partial_marker_consistency(tx_meta)
        self._validate_transaction_in_scope(tx)

    def post_get_validation(self, tx: BaseTransaction) -> None:
        """ Must be run before every save, will raise AssertionError or TransactionNotInAllowedScopeError

        A failure means there is a bug in the code that allowed the condition to reach the "get" code. This is a last
        second measure to prevent getting a transaction while using the wrong scope.
        """
        tx_meta = tx.get_metadata()
        self._validate_partial_marker_consistency(tx_meta)
        self._validate_transaction_in_scope(tx)

    def _validate_partial_marker_consistency(self, tx_meta: TransactionMetadata) -> None:
        voided_by = tx_meta.get_frozen_voided_by()
        # XXX: PARTIALLY_VALIDATED_ID must be included if the tx is fully connected and must not be included otherwise
        has_partially_validated_marker = self._settings.PARTIALLY_VALIDATED_ID in voided_by
        validation_is_fully_connected = tx_meta.validation.is_fully_connected()
        assert (not has_partially_validated_marker) == validation_is_fully_connected, \
               'Inconsistent ValidationState and voided_by'

    def _validate_transaction_in_scope(self, tx: BaseTransaction) -> None:
        if not self.get_allow_scope().is_allowed(tx):
            tx_meta = tx.get_metadata()
            raise TransactionNotInAllowedScopeError(tx.hash_hex, self.get_allow_scope().name, tx_meta.validation.name)

    @abstractmethod
    def remove_transaction(self, tx: BaseTransaction) -> None:
        """Remove the tx.

        :param tx: Transaction to be removed
        """
        if self.indexes is not None:
            self.del_from_indexes(tx, remove_all=True, relax_assert=True)

    @abstractmethod
    def transaction_exists(self, hash_bytes: bytes) -> bool:
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

    def compare_bytes_with_local_tx(self, tx: BaseTransaction) -> bool:
        """Compare byte-per-byte `tx` with the local transaction."""
        # XXX: we have to accept any scope because we only want to know what bytes we have stored
        with tx_allow_context(self, allow_scope=TxAllowScope.ALL):
            local_tx = self.get_transaction(tx.hash)
        local_tx_bytes = bytes(local_tx)
        tx_bytes = bytes(tx)
        if tx_bytes == local_tx_bytes:
            return True
        self.log.critical('non-equal transactions with same id', tx_id=tx.hash.hex(),
                          local_tx=local_tx_bytes.hex(), tx=tx_bytes.hex())
        return False

    @abstractmethod
    def _get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        """Returns the transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

    def disable_lock(self) -> None:
        """ Turn off lock
        """
        self._should_lock = False

    def enable_lock(self) -> None:
        """ Turn on lock
        """
        self._should_lock = True

    def _get_lock(self, hash_bytes: bytes) -> Optional[Lock]:
        """ Get lock for tx hash in the weakref dictionary
        """
        if not self._should_lock:
            return None

        with self._weakref_lock:
            lock = self._weakref_lock_per_hash.get(hash_bytes, None)
            if lock is None:
                lock = Lock()
                self._weakref_lock_per_hash[hash_bytes] = lock
        return lock

    def get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        """Acquire the lock and get the transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        if self._should_lock:
            lock = self._get_lock(hash_bytes)
            assert lock is not None
            with lock:
                tx = self._get_transaction(hash_bytes)
        else:
            tx = self._get_transaction(hash_bytes)
        self.post_get_validation(tx)
        return tx

    def get_tx(self, vertex_id: VertexId) -> Transaction:
        """Return a Transaction."""
        tx = self.get_transaction(vertex_id)
        assert isinstance(tx, Transaction)
        return tx

    def get_token_creation_transaction(self, hash_bytes: bytes) -> TokenCreationTransaction:
        """Acquire the lock and get the token creation transaction with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :raises TransactionDoesNotExist: If the transaction with the given hash does not exist.
        :raises TokenCreationTransactionDoesNotExist: If the transaction exists but is not a TokenCreationTransaction.
        :return: The TokenCreationTransaction instance.
        """
        from hathor.transaction.token_creation_tx import TokenCreationTransaction

        tx = self.get_transaction(hash_bytes)
        if not isinstance(tx, TokenCreationTransaction):
            raise TokenCreationTransactionDoesNotExist(hash_bytes)
        return tx

    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Return a block in the best blockchain from the height index. This is fast."""
        assert self.indexes is not None
        ancestor_hash = self.indexes.height.get(height)

        return None if ancestor_hash is None else self.get_block(ancestor_hash)

    def get_metadata(self, hash_bytes: bytes) -> Optional[TransactionMetadata]:
        """Returns the transaction metadata with hash `hash_bytes`.

        :param hash_bytes: Hash in bytes that will be checked.
        :rtype :py:class:`hathor.transaction.TransactionMetadata`
        """
        try:
            tx = self.get_transaction(hash_bytes)
            return tx.get_metadata(use_storage=False)
        except TransactionDoesNotExist:
            return None

    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        """Return all vertices (transactions and blocks) within the allowed scope.
        """
        # It is necessary to retain a copy of the current scope because this method will yield
        # and the scope may undergo changes. By doing so, we ensure the usage of the scope at the
        # time of iterator creation.
        scope = self.get_allow_scope()
        for tx in self._get_all_transactions():
            if scope.is_allowed(tx):
                yield tx

    @abstractmethod
    def _get_all_transactions(self) -> Iterator[BaseTransaction]:
        """Internal implementation that iterates over all transactions/blocks.
        """
        raise NotImplementedError

    @abstractmethod
    def get_vertices_count(self) -> int:
        # TODO: verify the following claim:
        """Return the number of transactions/blocks stored.

        :rtype int
        """
        raise NotImplementedError

    @abstractproperty
    def latest_timestamp(self) -> int:
        raise NotImplementedError

    @abstractproperty
    def first_timestamp(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_best_block_tips(self, timestamp: Optional[float] = None, *, skip_cache: bool = False) -> list[bytes]:
        """ Return a list of blocks that are heads in a best chain. It must be used when mining.

        When more than one block is returned, it means that there are multiple best chains and
        you can choose any of them.
        """
        if timestamp is None and not skip_cache and self._best_block_tips_cache is not None:
            return self._best_block_tips_cache[:]

        best_score: int = 0
        best_tip_blocks: list[bytes] = []

        for block_hash in (x.data for x in self.get_block_tips(timestamp)):
            meta = self.get_metadata(block_hash)
            assert meta is not None
            if meta.voided_by and meta.voided_by != set([block_hash]):
                # If anyone but the block itself is voiding this block, then it must be skipped.
                continue
            if meta.score == best_score:
                best_tip_blocks.append(block_hash)
            elif meta.score > best_score:
                best_score = meta.score
                best_tip_blocks = [block_hash]

        # XXX: if there's more than one we filter it so it's the smallest hash
        if len(best_tip_blocks) > 1:
            best_tip_blocks = [min(best_tip_blocks)]

        if timestamp is None:
            self._best_block_tips_cache = best_tip_blocks[:]
        return best_tip_blocks

    @abstractmethod
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        assert self.indexes is not None
        return self.indexes.height.get_n_height_tips(n_blocks)

    def get_weight_best_block(self) -> float:
        heads = [self.get_transaction(h) for h in self.get_best_block_tips()]
        highest_weight = 0.0
        for head in heads:
            if head.weight > highest_weight:
                highest_weight = head.weight

        return highest_weight

    def get_height_best_block(self) -> int:
        """ Iterate over best block tips and get the highest height
        """
        heads = [self.get_transaction(h) for h in self.get_best_block_tips()]
        highest_height = 0
        for head in heads:
            assert isinstance(head, Block)
            head_height = head.get_height()
            if head_height > highest_height:
                highest_height = head_height

        return highest_height

    @cpu.profiler('get_merkle_tree')
    def get_merkle_tree(self, timestamp: int) -> tuple[bytes, list[bytes]]:
        """ Generate a hash to check whether the DAG is the same at that timestamp.

        :rtype: tuple[bytes(hash), list[bytes(hash)]]
        """
        if self._all_tips_cache is not None and timestamp >= self._all_tips_cache.timestamp:
            return self._all_tips_cache.merkle_tree, self._all_tips_cache.hashes

        intervals = self.get_all_tips(timestamp)
        if timestamp >= self.latest_timestamp:
            # get_all_tips will add to cache in that case
            assert self._all_tips_cache is not None
            return self._all_tips_cache.merkle_tree, self._all_tips_cache.hashes

        return self.calculate_merkle_tree(intervals)

    def calculate_merkle_tree(self, intervals: set[Interval]) -> tuple[bytes, list[bytes]]:
        """ Generate a hash of the transactions at the intervals

        :rtype: tuple[bytes(hash), list[bytes(hash)]]
        """
        hashes = [x.data for x in intervals]
        hashes.sort()

        merkle = hashlib.sha256()
        for h in hashes:
            merkle.update(h)

        return merkle.digest(), hashes

    @abstractmethod
    def get_block_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_all_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_tx_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_newest_blocks(self, count: int) -> tuple[list[Block], bool]:
        """ Get blocks from the newest to the oldest

        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest_txs(self, count: int) -> tuple[list[BaseTransaction], bool]:
        """ Get transactions from the newest to the oldest

        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> tuple[list[Block], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> tuple[list[BaseTransaction], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[BaseTransaction], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[BaseTransaction], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def _manually_initialize(self) -> None:
        # XXX: maybe refactor, this is actually part of the public interface
        """Caches must be initialized. This function should not be called, because
        usually the HathorManager will handle all this initialization.
        """
        pass

    def topological_iterator(self) -> Iterator[BaseTransaction]:
        """This method will return the fastest topological iterator available based on the database state.

        This will be:

        - self._topological_sort_timestamp_index() when the timestamp index is up-to-date
        - self._topological_sort_metadata() otherwise, metadata is assumed to be up-to-date
        - self._topological_sort_dfs() when the private property `_always_use_topological_dfs` is set to `True`
        """
        # TODO: we currently assume that metadata is up-to-date, and thus this method can only run when that assumption
        #       is known to be true, but we could add a mechanism similar to what indexes use to know they're
        #       up-to-date and get rid of that assumption so this method can be used without having to make any
        #       assumptions
        assert self.indexes is not None

        if self._always_use_topological_dfs:
            self.log.debug('force choosing DFS iterator')
            return self._topological_sort_dfs()

        db_last_started_at = self.get_last_started_at()
        sorted_all_db_name = self.indexes.sorted_all.get_db_name()
        if sorted_all_db_name is None:
            can_use_timestamp_index = False
        else:
            sorted_all_index_last_started_at = self.get_index_last_started_at(sorted_all_db_name)
            can_use_timestamp_index = db_last_started_at == sorted_all_index_last_started_at

        iter_tx: Iterator[BaseTransaction]
        if can_use_timestamp_index:
            self.log.debug('choosing timestamp-index iterator')
            iter_tx = self._topological_sort_timestamp_index()
        else:
            self.log.debug('choosing metadata iterator')
            iter_tx = self._topological_sort_metadata()

        return iter_tx

    @abstractmethod
    def _topological_sort_dfs(self) -> Iterator[BaseTransaction]:
        """Return an iterable of the transactions in topological ordering, i.e., from genesis to the most recent
        transactions. The order is important because the transactions are always valid --- their parents and inputs
        exist. This method is designed to be used for rebuilding metadata or indexes, that is, it does not make use of
        any metadata, only the transactions parents data is used and no index is used.

        XXX: blocks are prioritized so as soon as a block can be yielded it will, which means that it is possible for a
        block to be yielded much sooner than an older transaction that isn't being confirmed by that block.
        """
        raise NotImplementedError

    @abstractmethod
    def _topological_sort_timestamp_index(self) -> Iterator[BaseTransaction]:
        """Return an iterable of the transactions in topological ordering, i.e., from genesis to the most recent
        transactions. The order is important because the transactions are always valid --- their parents and inputs
        exist. This method makes use of the timestamp index, so it is crucial that that index is correct and complete.

        XXX: blocks are still prioritized over transactions, but only within the same timestamp, which means that it
        will yield a different sequence than _topological_sort_dfs, but the sequence is still topological.
        """
        raise NotImplementedError

    @abstractmethod
    def _topological_sort_metadata(self) -> Iterator[BaseTransaction]:
        """Return an iterable of the transactions in topological ordering, using only info from metadata.

        This is about as good as _topological_sort_timestamp_index but only needs the transaction's metadata to be
        consistent and up-to-date. It could replace _topological_sort_timestamp_index if we can show it is faster or at
        least not slower by most practical cases.
        """
        raise NotImplementedError

    @abstractmethod
    def add_to_indexes(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def del_from_indexes(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_block_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_tx_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_genesis(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        """Returning hardcoded genesis block and transactions."""
        raise NotImplementedError

    @abstractmethod
    def get_all_genesis(self) -> set[BaseTransaction]:
        raise NotImplementedError

    @abstractmethod
    def get_transactions_before(self, hash_bytes: bytes, num_blocks: int = 100) -> list[BaseTransaction]:
        """Run a BFS starting from the giving `hash_bytes`.

        :param hash_bytes: Starting point of the BFS, either a block or a transaction.
        :param num_blocks: Number of blocks to be return.
        :return: List of transactions
        """
        raise NotImplementedError

    @abstractmethod
    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> list[Block]:
        """Run a BFS starting from the giving `hash_bytes`.

        :param hash_bytes: Starting point of the BFS.
        :param num_blocks: Number of blocks to be return.
        :return: List of transactions
        """
        raise NotImplementedError

    def add_value(self, key: str, value: str) -> None:
        """ Save value on storage
            Need to be a string to support all storages, including rocksdb, that needs bytes
        """
        raise NotImplementedError

    def remove_value(self, key: str) -> None:
        """ Remove value from storage
        """
        raise NotImplementedError

    def get_value(self, key: str) -> Optional[str]:
        """ Get value from storage
        """
        raise NotImplementedError

    def get_network(self) -> Optional[str]:
        """ Return the stored network name
        """
        return self.get_value(self._network_attribute)

    def set_network(self, network: str) -> None:
        """ Save the network name
        """
        return self.add_value(self._network_attribute, network)

    def start_running_manager(self, execution_manager: ExecutionManager) -> None:
        """ Save on storage that manager is running
        """
        execution_manager.register_on_crash_callback(self.on_full_node_crash)
        self.add_value(self._manager_running_attribute, '1')

    def stop_running_manager(self) -> None:
        """ Remove from storage that manager is running
        """
        self.remove_value(self._manager_running_attribute)

    def is_running_manager(self) -> bool:
        """ Return if the manager is running or was running and a sudden crash stopped the full node
        """
        return self.get_value(self._manager_running_attribute) == '1'

    def on_full_node_crash(self) -> None:
        """Save on storage that the full node crashed and cannot be recovered."""
        self.add_value(self._full_node_crashed_attribute, '1')

    def is_full_node_crashed(self) -> bool:
        """Return whether the full node was crashed."""
        return self.get_value(self._full_node_crashed_attribute) == '1'

    def get_last_started_at(self) -> int:
        """ Return the timestamp when the database was last started.
        """
        # XXX: defaults to 1 just to force indexes initialization, by being higher than 0
        return int(self.get_value(self._last_start_attribute) or NULL_LAST_STARTED_AT)

    def set_last_started_at(self, timestamp: int) -> None:
        """ Update the timestamp when the database was last started.
        """
        self.add_value(self._last_start_attribute, str(timestamp))

    def get_index_last_started_at(self, index_db_name: str) -> int:
        """ Return the timestamp when an index was last started.
        """
        attr_name = INDEX_ATTR_PREFIX + index_db_name
        return int(self.get_value(attr_name) or NULL_INDEX_LAST_STARTED_AT)

    def set_index_last_started_at(self, index_db_name: str, timestamp: int) -> None:
        """ Update the timestamp when a specific index was last started.
        """
        attr_name = INDEX_ATTR_PREFIX + index_db_name
        self.add_value(attr_name, str(timestamp))

    def update_last_started_at(self, timestamp: int) -> None:
        """ Updates the respective timestamps of when the node was last started.

        Using this mehtod ensures that the same timestamp is being used and the correct indexes are being selected.
        """
        assert self.indexes is not None
        self.set_last_started_at(timestamp)
        for index in self.indexes.iter_all_indexes():
            index_db_name = index.get_db_name()
            if index_db_name is None:
                continue
            self.set_index_last_started_at(index_db_name, timestamp)

    @abstractmethod
    def flush(self) -> None:
        """Flushes the storage. It's called during shutdown of the node, for instance.

           Should be implemented by storages that provide some kind of in-memory cache
        """
        raise NotImplementedError

    def iter_mempool_tips_from_tx_tips(self) -> Iterator[Transaction]:
        """ Same behavior as the mempool index for iterating over the tips.

        This basically means that the returned iterator will yield all transactions that are tips and have not been
        confirmed by a block on the best chain.

        This method requires indexes to be enabled.
        """
        assert self.indexes is not None
        tx_tips = self.indexes.tx_tips

        for interval in tx_tips[self.latest_timestamp + 1]:
            tx = self.get_transaction(interval.data)
            tx_meta = tx.get_metadata()
            assert isinstance(tx, Transaction)  # XXX: tx_tips only has transactions
            # XXX: skip txs that have already been confirmed
            if tx_meta.first_block:
                continue
            yield tx

    def iter_mempool_from_tx_tips(self) -> Iterator[Transaction]:
        """ Same behavior as the mempool index for iterating over all mempool transactions.

        This basically means that the returned iterator will yield all transactions that have not been confirmed by a
        block on the best chain. Order is not guaranteed to be the same as in the mempool index.

        This method requires indexes to be enabled.
        """
        from hathor.transaction.storage.traversal import BFSTimestampWalk

        root = self.iter_mempool_tips_from_tx_tips()
        walk = BFSTimestampWalk(self, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=False)
        for tx in walk.run(root):
            tx_meta = tx.get_metadata()
            # XXX: skip blocks and tx-tips that have already been confirmed
            if tx_meta.first_block is not None or tx.is_block:
                walk.skip_neighbors(tx)
            else:
                assert isinstance(tx, Transaction)
                yield tx

    def iter_mempool_tips_from_best_index(self) -> Iterator[Transaction]:
        """Get tx tips in the mempool, using the best available index (mempool_tips or tx_tips)"""
        assert self.indexes is not None
        if self.indexes.mempool_tips is not None:
            yield from self.indexes.mempool_tips.iter(self)
        else:
            yield from self.iter_mempool_tips_from_tx_tips()

    def iter_mempool_from_best_index(self) -> Iterator[Transaction]:
        """Get all transactions in the mempool, using the best available index (mempool_tips or tx_tips)"""
        assert self.indexes is not None
        if self.indexes.mempool_tips is not None:
            yield from self.indexes.mempool_tips.iter_all(self)
        else:
            yield from self.iter_mempool_from_tx_tips()

    def _construct_genesis_block(self) -> Block:
        """Return the genesis block."""
        block = Block(
            settings=self._settings,
            storage=self,
            nonce=self._settings.GENESIS_BLOCK_NONCE,
            timestamp=self._settings.GENESIS_BLOCK_TIMESTAMP,
            weight=self._settings.MIN_BLOCK_WEIGHT,
            outputs=[
                TxOutput(self._settings.GENESIS_TOKENS, self._settings.GENESIS_OUTPUT_SCRIPT),
            ],
        )
        block.update_hash()

        assert block.hash == self._settings.GENESIS_BLOCK_HASH, \
               f'{block.hash.hex()} != {self._settings.GENESIS_BLOCK_HASH.hex()}'
        return block

    def _construct_genesis_tx1(self) -> Transaction:
        """Return the genesis tx1."""
        tx1 = Transaction(
            settings=self._settings,
            storage=self,
            nonce=self._settings.GENESIS_TX1_NONCE,
            timestamp=self._settings.GENESIS_TX1_TIMESTAMP,
            weight=self._settings.MIN_TX_WEIGHT,
        )
        tx1.update_hash()

        assert tx1.hash == self._settings.GENESIS_TX1_HASH, \
               f'{tx1.hash.hex()} != {self._settings.GENESIS_TX1_HASH.hex()}'
        return tx1

    def _construct_genesis_tx2(self) -> Transaction:
        """Return the genesis tx2."""
        tx2 = Transaction(
            settings=self._settings,
            storage=self,
            nonce=self._settings.GENESIS_TX2_NONCE,
            timestamp=self._settings.GENESIS_TX2_TIMESTAMP,
            weight=self._settings.MIN_TX_WEIGHT,
        )
        tx2.update_hash()

        assert tx2.hash == self._settings.GENESIS_TX2_HASH, \
               f'{tx2.hash.hex()} != {self._settings.GENESIS_TX2_HASH.hex()}'
        return tx2

    def get_parent_block(self, block: Block) -> Block:
        return block.get_block_parent()

    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        return self.get_transaction(vertex_id)

    def get_block(self, block_id: VertexId) -> Block:
        block = self.get_vertex(block_id)
        assert isinstance(block, Block)
        return block

    def can_validate_full(self, vertex: Vertex) -> bool:
        """ Check if a vertex is ready to be fully validated, either all deps are full-valid or one is invalid.
        """
        if vertex.is_genesis:
            return True
        deps = vertex.get_all_dependencies()
        all_exist = True
        all_valid = True
        # either they all exist and are fully valid
        for dep in deps:
            meta = self.get_metadata(dep)
            if meta is None:
                all_exist = False
                continue
            if not meta.validation.is_fully_connected():
                all_valid = False
            if meta.validation.is_invalid():
                # or any of them is invalid (which would make this one invalid too)
                return True
        return all_exist and all_valid

    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self.allow_partially_validated_context():
            return self.transaction_exists(vertex_id)

    def get_nc_block_storage(self, block: Block) -> NCBlockStorage:
        """Return a block storage for the given block."""
        return self._nc_storage_factory.get_block_storage_from_block(block)

    def get_nc_storage(self, block: Block, contract_id: ContractId) -> NCContractStorage:
        """Return a contract storage with the contract state at a given block."""
        from hathor.nanocontracts.types import ContractId, VertexId as NCVertexId
        if not block.is_genesis:
            block_storage = self._nc_storage_factory.get_block_storage_from_block(block)
        else:
            block_storage = self._nc_storage_factory.get_empty_block_storage()

        return block_storage.get_contract_storage(ContractId(NCVertexId(contract_id)))

    def _get_blueprint(self, blueprint_id: BlueprintId) -> type[Blueprint] | OnChainBlueprint:
        assert self.nc_catalog is not None

        if blueprint_class := self.nc_catalog.get_blueprint_class(blueprint_id):
            return blueprint_class

        self.log.debug(
            'blueprint_id not in the catalog, looking for on-chain blueprint',
            blueprint_id=blueprint_id.hex()
        )
        return self.get_on_chain_blueprint(blueprint_id)

    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str:
        """Returns the source code associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        import inspect

        from hathor.nanocontracts import OnChainBlueprint

        blueprint = self._get_blueprint(blueprint_id)
        if isinstance(blueprint, OnChainBlueprint):
            return self.get_on_chain_blueprint(blueprint_id).code.text
        else:
            module = inspect.getmodule(blueprint)
            assert module is not None
            return inspect.getsource(module)

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        """Returns the blueprint class associated with the given blueprint_id.

        The blueprint class could be in the catalog (first search), or it could be the tx_id of an on-chain blueprint.
        """
        from hathor.nanocontracts import OnChainBlueprint
        blueprint = self._get_blueprint(blueprint_id)
        if isinstance(blueprint, OnChainBlueprint):
            return blueprint.get_blueprint_class()
        else:
            return blueprint

    def get_on_chain_blueprint(self, blueprint_id: BlueprintId) -> OnChainBlueprint:
        """Return an on-chain blueprint transaction."""
        from hathor.nanocontracts import OnChainBlueprint
        from hathor.nanocontracts.exception import (
            BlueprintDoesNotExist,
            OCBBlueprintNotConfirmed,
            OCBInvalidBlueprintVertexType,
        )
        try:
            blueprint_tx = self.get_transaction(blueprint_id)
        except TransactionDoesNotExist:
            self.log.debug('no transaction with the given id found', blueprint_id=blueprint_id.hex())
            raise BlueprintDoesNotExist(blueprint_id.hex())
        if not isinstance(blueprint_tx, OnChainBlueprint):
            raise OCBInvalidBlueprintVertexType(blueprint_id.hex())
        tx_meta = blueprint_tx.get_metadata()
        if tx_meta.voided_by or not tx_meta.first_block:
            raise OCBBlueprintNotConfirmed(blueprint_id.hex())
        # XXX: maybe use N blocks confirmation, like reward-locks
        return blueprint_tx

    @abstractmethod
    def migrate_vertex_children(self) -> None:
        raise NotImplementedError


class BaseTransactionStorage(TransactionStorage):
    indexes: Optional[IndexesManager]

    def __init__(
        self,
        indexes: Optional[IndexesManager] = None,
        pubsub: Optional[Any] = None,
        *,
        settings: HathorSettings,
        nc_storage_factory: NCStorageFactory,
        vertex_children_service: VertexChildrenService,
    ) -> None:
        super().__init__(
            settings=settings,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
        )

        # Pubsub is used to publish tx voided and winner but it's optional
        self.pubsub = pubsub

        # Indexes.
        self.indexes = indexes

        # Either save or verify all genesis.
        self._save_or_verify_genesis()

        self._latest_n_height_tips: list[HeightInfo] = []

    @property
    def latest_timestamp(self) -> int:
        assert self.indexes is not None
        return self.indexes.info.get_latest_timestamp()

    @property
    def first_timestamp(self) -> int:
        assert self.indexes is not None
        return self.indexes.info.get_first_timestamp()

    @abstractmethod
    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        raise NotImplementedError

    def reset_indexes(self) -> None:
        """Reset all indexes. This function should not be called unless you know what you are doing."""
        assert self.indexes is not None, 'Cannot reset indexes because they have not been enabled.'
        self.indexes.force_clear_all()
        self.update_best_block_tips_cache(None)
        self._all_tips_cache = None

    def remove_cache(self) -> None:
        """Remove all caches in case we don't need it."""
        self.indexes = None

    def get_best_block_tips(self, timestamp: Optional[float] = None, *, skip_cache: bool = False) -> list[bytes]:
        return super().get_best_block_tips(timestamp, skip_cache=skip_cache)

    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        block = self.get_best_block()
        if self._latest_n_height_tips:
            best_block = self._latest_n_height_tips[0]
            if block.hash == best_block.id and n_blocks <= len(self._latest_n_height_tips):
                return self._latest_n_height_tips[:n_blocks]

        self._latest_n_height_tips = super().get_n_height_tips(n_blocks)
        return self._latest_n_height_tips[:n_blocks]

    def get_weight_best_block(self) -> float:
        return super().get_weight_best_block()

    def get_block_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        return self.indexes.block_tips[timestamp]

    def get_tx_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        tips = self.indexes.tx_tips[timestamp]

        if __debug__:
            # XXX: this `for` is for assert only and thus is inside `if __debug__:`
            for interval in tips:
                meta = self.get_metadata(interval.data)
                assert meta is not None
                # assert not meta.voided_by

        return tips

    def get_all_tips(self, timestamp: Optional[float] = None) -> set[Interval]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        if timestamp is None:
            timestamp = self.latest_timestamp

        if self._all_tips_cache is not None and timestamp >= self._all_tips_cache.timestamp:
            assert self._all_tips_cache.timestamp == self.latest_timestamp
            return self._all_tips_cache.tips

        tips = self.indexes.all_tips[timestamp]
        if timestamp >= self.latest_timestamp:
            merkle_tree, hashes = self.calculate_merkle_tree(tips)
            self._all_tips_cache = AllTipsCache(self.latest_timestamp, tips, merkle_tree, hashes)

        return tips

    def get_newest_blocks(self, count: int) -> tuple[list[Block], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_newest(count)
        blocks = [cast(Block, self.get_transaction(block_hash)) for block_hash in block_hashes]
        return blocks, has_more

    def get_newest_txs(self, count: int) -> tuple[list[BaseTransaction], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_newest(count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[Block], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_older(timestamp, hash_bytes, count)
        blocks = [cast(Block, self.get_transaction(block_hash)) for block_hash in block_hashes]
        return blocks, has_more

    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> tuple[list[BaseTransaction], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_newer(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[BaseTransaction], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_older(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> tuple[list[BaseTransaction], bool]:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_newer(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def _manually_initialize(self) -> None:
        self._manually_initialize_indexes()

    def _manually_initialize_indexes(self) -> None:
        if self.indexes is not None:
            self.indexes._manually_initialize(self)

    def _topological_sort_timestamp_index(self) -> Iterator[BaseTransaction]:
        assert self.indexes is not None

        cur_timestamp: Optional[int] = None
        cur_blocks: list[Block] = []
        cur_txs: list[Transaction] = []
        for tx_hash in self.indexes.sorted_all.iter():
            tx = self.get_transaction(tx_hash)
            if tx.timestamp != cur_timestamp:
                yield from cur_blocks
                cur_blocks.clear()
                yield from cur_txs
                cur_txs.clear()
                cur_timestamp = tx.timestamp
            if tx.is_block:
                assert isinstance(tx, Block)
                cur_blocks.append(tx)
            else:
                assert isinstance(tx, Transaction)
                cur_txs.append(tx)
        yield from cur_blocks
        yield from cur_txs

    def _topological_sort_metadata(self, *, include_partial: bool = False) -> Iterator[BaseTransaction]:
        import heapq
        from dataclasses import dataclass, field

        @dataclass(order=True)
        class Item:
            timestamp: int
            # XXX: because bools are ints, and False==0, True==1, is_transaction=False < is_transaction=True, which
            #      will make blocks be prioritized over transactions with the same timestamp
            is_transaction: bool
            tx: BaseTransaction = field(compare=False)

            def __init__(self, tx: BaseTransaction):
                self.timestamp = tx.timestamp
                self.is_transaction = tx.is_transaction
                self.tx = tx

        to_visit: list[Item] = list(map(Item, self.get_all_genesis()))
        seen: set[bytes] = set()
        heapq.heapify(to_visit)
        while to_visit:
            item = heapq.heappop(to_visit)
            yield item.tx
            # XXX: We can safely discard because no other tx will try to visit this one, since timestamps are strictly
            #      higher in children, meaning we cannot possibly have item.tx as a descendant of any tx in to_visit.
            seen.discard(item.tx.hash)
            for child_tx_hash in item.tx.get_children():
                if child_tx_hash in seen:
                    continue
                child_tx = self.get_transaction(child_tx_hash)
                heapq.heappush(to_visit, Item(child_tx))
                seen.add(child_tx_hash)

    def _topological_sort_dfs(self) -> Iterator[BaseTransaction]:
        # TODO We must optimize this algorithm to remove the `visited` set.
        #      It will consume too much memory when the number of transactions is big.
        #      A solution would be to store the ordering in disk, probably indexing by tx's height.
        #      Sorting the vertices by the lengths of their longest incoming paths produces a topological
        #      ordering (Dekel, Nassimi & Sahni 1981). See: https://epubs.siam.org/doi/10.1137/0210049
        #      See also: https://gitlab.com/HathorNetwork/hathor-python/merge_requests/31
        visited: dict[bytes, int] = dict()  # dict[bytes, int]
        for tx in self.get_all_transactions():
            if not tx.is_block:
                continue
            yield from self._run_topological_sort_dfs(tx, visited)
        for tx in self.get_all_transactions():
            yield from self._run_topological_sort_dfs(tx, visited)

    def _run_topological_sort_dfs(self, root: BaseTransaction, visited: dict[bytes, int]) -> Iterator[BaseTransaction]:
        if root.hash in visited:
            return

        stack = [root]
        while stack:
            tx = stack[-1]
            if tx.hash in visited:
                if visited[tx.hash] == 0:
                    visited[tx.hash] = 1  # 1 = Visited
                    yield tx
                assert tx == stack.pop()
                continue

            visited[tx.hash] = 0  # 0 = Visit in progress

            # The parents are reversed to go first through the blocks and only then
            # go through the transactions. It works because blocks must have the
            # previous block as the first parent. For transactions, the order does not
            # matter.
            for parent_hash in tx.parents[::-1]:
                if parent_hash not in visited:
                    try:
                        parent = self.get_transaction(parent_hash)
                    except TransactionDoesNotExist:
                        # XXX: it's possible transactions won't exist because of missing dependencies
                        pass
                    else:
                        stack.append(parent)

            for txin in tx.inputs:
                if txin.tx_id not in visited:
                    try:
                        txinput = self.get_transaction(txin.tx_id)
                    except TransactionDoesNotExist:
                        # XXX: it's possible transactions won't exist because of missing dependencies
                        pass
                    else:
                        stack.append(txinput)

    def add_to_indexes(self, tx: BaseTransaction) -> None:
        if self.indexes is None:
            if self._saving_genesis:
                # XXX: avoid failing on some situations where this is called before we know it's OK to skip
                #      see: https://github.com/HathorNetwork/hathor-core/pull/436
                return
            else:
                raise NotImplementedError
        assert self.indexes is not None
        self._all_tips_cache = None
        self.indexes.add_tx(tx)

    def del_from_indexes(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        self.indexes.del_tx(tx, remove_all=remove_all, relax_assert=relax_assert)

    def get_block_count(self) -> int:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        return self.indexes.info.get_block_count()

    def get_tx_count(self) -> int:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        return self.indexes.info.get_tx_count()

    def get_vertices_count(self) -> int:
        if self.indexes is None:
            raise NotImplementedError
        assert self.indexes is not None
        return self.indexes.info.get_vertices_count()

    def get_genesis(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        assert self._genesis_cache is not None
        return self._genesis_cache.get(hash_bytes, None)

    def get_all_genesis(self) -> set[BaseTransaction]:
        assert self._genesis_cache is not None
        return set(self._genesis_cache.values())

    def get_transactions_before(self, hash_bytes: bytes,
                                num_blocks: int = 100) -> list[BaseTransaction]:  # pragma: no cover
        ref_tx = self.get_transaction(hash_bytes)
        visited: dict[bytes, int] = dict()  # dict[bytes, int]
        result = [x for x in self._run_topological_sort_dfs(ref_tx, visited) if not x.is_block]
        result = result[-num_blocks:]
        return result

    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> list[Block]:
        ref_tx = self.get_transaction(hash_bytes)
        if not ref_tx.is_block:
            raise TransactionIsNotABlock
        result = []  # list[Block]
        pending_visits = deque(ref_tx.parents)  # list[bytes]
        used = set(pending_visits)  # set[bytes]
        while pending_visits:
            tx_hash = pending_visits.popleft()
            tx = self.get_transaction(tx_hash)
            if not tx.is_block:
                continue
            assert isinstance(tx, Block)
            result.append(tx)
            if len(result) >= num_blocks:
                break
            for parent_hash in tx.parents:
                if parent_hash not in used:
                    used.add(parent_hash)
                    pending_visits.append(parent_hash)
        return result

    def flush(self) -> None:
        pass
