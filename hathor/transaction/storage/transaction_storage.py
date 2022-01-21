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

import hashlib
from abc import ABC, abstractmethod, abstractproperty
from collections import deque
from threading import Lock
from typing import Any, Dict, FrozenSet, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple, cast
from weakref import WeakValueDictionary

from intervaltree.interval import Interval
from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.indexes import IndexesManager, MemoryIndexesManager
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction.base_transaction import BaseTransaction
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionIsNotABlock
from hathor.transaction.transaction import Transaction
from hathor.transaction.transaction_metadata import TransactionMetadata, ValidationState
from hathor.util import not_none

settings = HathorSettings()


INF_HEIGHT: int = 1_000_000_000_000


class AllTipsCache(NamedTuple):
    timestamp: int
    tips: Set[Interval]
    merkle_tree: bytes
    hashes: List[bytes]


class _DirDepValue(Dict[bytes, ValidationState]):
    """This class is used to add a handy method to values on dependency indexes."""

    def is_ready(self) -> bool:
        """True if all deps' validation are fully connected."""
        return all(val.is_fully_connected() for val in self.values())


class TransactionStorage(ABC):
    """Legacy sync interface, please copy @deprecated decorator when implementing methods."""

    pubsub: Optional[PubSubManager]
    with_index: bool
    indexes: Optional[IndexesManager]

    log = get_logger()

    def __init__(self):
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

        # Cache for the best block tips
        # This cache is updated in the consensus algorithm.
        self._best_block_tips_cache = None

        # If should create lock when getting a transaction
        self._should_lock = False

        # Provide local logger
        self.log = self.log.new()

        # Cache for the latest timestamp of all tips with merkle tree precalculated to be used on the sync algorithm
        # This cache is invalidated every time a new tx or block is added to the cache and
        # self._all_tips_cache.timestamp is always self.latest_timestamp
        self._all_tips_cache: Optional[AllTipsCache] = None

        # Initialize cache for genesis transactions.
        self._genesis_cache: Dict[bytes, BaseTransaction] = {}

        # Key storage attribute to save if the network stored is the expected network
        self._network_attribute: str = 'network'

        # Key storage attribute to save if the full node is running a full verification
        self._running_full_verification_attribute: str = 'running_full_verification'

        # Key storage attribute to save if the manager is running
        self._manager_running_attribute: str = 'manager_running'

        # Direct and reverse dependency mapping (i.e. needs and needed by)
        self._dir_dep_index: Dict[bytes, _DirDepValue] = {}
        self._rev_dep_index: Dict[bytes, Set[bytes]] = {}
        self._txs_with_deps_ready: Set[bytes] = set()

        # Needed txs (key: tx missing, value: requested by)
        self._needed_txs_index: Dict[bytes, Tuple[int, bytes]] = {}

    # rev-dep-index methods:

    def count_deps_index(self) -> int:
        """Count total number of txs with dependencies."""
        return len(self._dir_dep_index)

    def _get_validation_state(self, tx: bytes) -> ValidationState:
        """Query database for the validation state of a transaction, returns INITIAL when tx does not exist."""
        tx_meta = self.get_metadata(tx)
        if tx_meta is None:
            return ValidationState.INITIAL
        return tx_meta.validation

    def _update_deps(self, deps: _DirDepValue) -> None:
        """Propagate the new validation state of the given deps."""
        for tx, validation in deps.items():
            self._update_validation(tx, validation)

    def _update_validation(self, tx: bytes, validation: ValidationState) -> None:
        """Propagate the new validation state of a given dep."""
        for cousin in self._rev_dep_index[tx].copy():
            deps = self._dir_dep_index[cousin]
            # XXX: this check serves to avoid calling is_ready() when nothing changed
            if deps[tx] != validation:
                deps[tx] = validation
                if deps.is_ready():
                    self.del_from_deps_index(cousin)
                    self._txs_with_deps_ready.add(cousin)

    def add_to_deps_index(self, tx: bytes, deps: Iterable[bytes]) -> None:
        """Call to add all dependencies a transaction has."""
        # deps are immutable for a given hash
        _deps = _DirDepValue((dep, self._get_validation_state(dep)) for dep in deps)
        # short circuit add directly to ready
        if _deps.is_ready():
            self._txs_with_deps_ready.add(tx)
            return
        # add direct deps
        if __debug__ and tx in self._dir_dep_index:
            # XXX: dependencies set must be immutable
            assert self._dir_dep_index[tx].keys() == _deps.keys()
        self._dir_dep_index[tx] = _deps
        # add reverse dep
        for rev_dep in _deps:
            if rev_dep not in self._rev_dep_index:
                self._rev_dep_index[rev_dep] = set()
            self._rev_dep_index[rev_dep].add(tx)

    def del_from_deps_index(self, tx: bytes) -> None:
        """Call to remove tx from all reverse dependencies, for example when validation is complete."""
        _deps = self._dir_dep_index.pop(tx, _DirDepValue())
        for rev_dep in _deps.keys():
            rev_deps = self._rev_dep_index[rev_dep]
            if tx in rev_deps:
                rev_deps.remove(tx)
            if not rev_deps:
                del self._rev_dep_index[rev_dep]

    def is_ready_for_validation(self, tx: bytes) -> bool:
        """ Whether a tx can be fully validated (implies fully connected).
        """
        return tx in self._txs_with_deps_ready

    def remove_ready_for_validation(self, tx: bytes) -> None:
        """ Removes from ready for validation set.
        """
        self._txs_with_deps_ready.discard(tx)

    def next_ready_for_validation(self, *, dry_run: bool = False) -> Iterator[bytes]:
        """ Yields and removes all txs ready for validation even if they become ready while iterating.
        """
        if dry_run:
            cur_ready = self._txs_with_deps_ready.copy()
        else:
            cur_ready, self._txs_with_deps_ready = self._txs_with_deps_ready, set()
        while cur_ready:
            yield from iter(cur_ready)
            if dry_run:
                cur_ready = self._txs_with_deps_ready - cur_ready
            else:
                cur_ready, self._txs_with_deps_ready = self._txs_with_deps_ready, set()

    def iter_deps_index(self) -> Iterator[bytes]:
        """Iterate through all hashes depended by any tx or block."""
        yield from self._rev_dep_index.keys()

    def get_rev_deps(self, tx: bytes) -> FrozenSet[bytes]:
        """Get all txs that depend on the given tx (i.e. its reverse depdendencies)."""
        return frozenset(self._rev_dep_index.get(tx, set()))

    def children_from_deps(self, tx: bytes) -> List[bytes]:
        """Return the hashes of all reverse dependencies that are children of the given tx.

        That is, they depend on `tx` because they are children of `tx`, and not because `tx` is an input. This is
        useful for pre-filling the children metadata, which would otherwise only be updated when
        `update_initial_metadata` is called on the child-tx.
        """
        return [not_none(rev.hash) for rev in map(self.get_transaction, self.get_rev_deps(tx)) if tx in rev.parents]

    # needed-txs-index methods:

    def has_needed_tx(self) -> bool:
        """Whether there is any tx on the needed tx index."""
        return bool(self._needed_txs_index)

    def is_tx_needed(self, tx: bytes) -> bool:
        """Whether a tx is in the requested tx list."""
        return tx in self._needed_txs_index

    def needed_index_height(self, tx: bytes) -> int:
        """Indexed height from the needed tx index."""
        return self._needed_txs_index[tx][0]

    def remove_from_needed_index(self, tx: bytes) -> None:
        """Remove tx from needed txs index, tx doesn't need to be in the index."""
        self._needed_txs_index.pop(tx, None)

    def get_next_needed_tx(self) -> bytes:
        """Choose the start hash for downloading the needed txs"""
        # This strategy maximizes the chance to download multiple txs on the same stream
        # find the tx with highest "height"
        # XXX: we could cache this onto `needed_txs` so we don't have to fetch txs every time
        height, start_hash, tx = max((h, s, t) for t, (h, s) in self._needed_txs_index.items())
        self.log.debug('next needed tx start', needed=len(self._needed_txs_index), start=start_hash.hex(),
                       height=height, needed_tx=tx.hex())
        return start_hash

    def add_needed_deps(self, tx: BaseTransaction) -> None:
        if isinstance(tx, Block):
            height = tx.get_metadata().height
        else:
            assert isinstance(tx, Transaction)
            first_block = tx.get_metadata().first_block
            if first_block is None:
                # XXX: consensus did not run yet to update first_block, what should we do?
                #      I'm defaulting the height to `inf` (practically), this should make it heightest priority when
                #      choosing which transactions to fetch next
                height = INF_HEIGHT
            else:
                block = self.get_transaction(first_block)
                assert isinstance(block, Block)
                height = block.get_metadata().height
        # get_tx_parents is used instead of get_tx_dependencies because the remote will traverse the parent
        # tree, not # the dependency tree, eventually we should receive all tx dependencies and be able to validate
        # this transaction
        for tx_hash in tx.get_tx_parents():
            # It may happen that we have one of the dependencies already, so just add the ones we don't
            # have. We should add at least one dependency, otherwise this tx should be full validated
            if not self.transaction_exists(tx_hash):
                self._needed_txs_index[tx_hash] = (height, not_none(tx.hash))

    # all other methods:

    def update_best_block_tips_cache(self, tips_cache: List[bytes]) -> None:
        # XXX: check that the cache update is working properly, only used in unittests
        # XXX: this might not actually hold true in some cases, commenting out while we figure it out
        # if settings.SLOW_ASSERTS:
        #     calculated_tips = self.get_best_block_tips(skip_cache=True)
        #     self.log.debug('cached best block tips must match calculated',
        #                    calculated=[i.hex() for i in calculated_tips],
        #                    cached=[i.hex() for i in tips_cache])
        #     assert set(tips_cache) == set(calculated_tips)
        self._best_block_tips_cache = tips_cache

    def is_empty(self) -> bool:
        """True when only genesis is present, useful for checking for a fresh database."""
        return self.get_count_tx_blocks() <= 3

    def pre_init(self) -> None:
        """Storages can implement this to run code before transaction loading starts"""
        self._check_and_set_network()

    def _check_and_set_network(self) -> None:
        """Check the network name is as expected and try to set it when none is present"""
        from hathor.transaction.storage.exceptions import WrongNetworkError

        network = settings.NETWORK_NAME
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
        for tx in self._get_genesis_from_settings():
            try:
                assert tx.hash is not None
                tx2 = self.get_transaction(tx.hash)
                assert tx == tx2
            except TransactionDoesNotExist:
                self.save_transaction(tx, add_to_indexes=True)
                tx2 = tx
            assert tx2.hash is not None
            self._genesis_cache[tx2.hash] = tx2

    def _get_genesis_from_settings(self) -> List[BaseTransaction]:
        """Return all genesis from settings."""
        from hathor.transaction.genesis import _get_genesis_transactions_unsafe
        return _get_genesis_transactions_unsafe(self)

    def _save_to_weakref(self, tx: BaseTransaction) -> None:
        """ Save transaction to weakref.
        """
        if self._tx_weakref_disabled:
            return
        assert tx.hash is not None
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
        assert tx.hash is not None
        self._tx_weakref.pop(tx.hash, None)

    def get_transaction_from_weakref(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        """ Get a transaction from weakref if it exists. Otherwise, returns None.
        """
        if self._tx_weakref_disabled:
            return None
        return self._tx_weakref.get(hash_bytes, None)

    def _enable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = False

    def _disable_weakref(self) -> None:
        """ Weakref should never be disabled unless you know exactly what you are doing.
        """
        self._tx_weakref_disabled = True

    @abstractmethod
    def save_transaction(self: 'TransactionStorage', tx: BaseTransaction, *, only_metadata: bool = False,
                         add_to_indexes: bool = False) -> None:
        # XXX: although this method is abstract (because a subclass must implement it) the implementer
        #      should call the base implementation for correctly interacting with the index
        """Saves the tx.

        :param tx: Transaction to save
        :param only_metadata: Don't save the transaction, only the metadata of this transaction
        :param add_to_indexes: Add this transaction to the indexes
        """
        meta = tx.get_metadata()
        if tx.hash in self._rev_dep_index:
            self._update_validation(tx.hash, meta.validation)

        # XXX: we can only add to cache and publish txs that are fully connected (which also implies it's valid)
        if not meta.validation.is_fully_connected():
            return

        if self.pubsub:
            if not meta.voided_by:
                self.pubsub.publish(HathorEvents.STORAGE_TX_WINNER, tx=tx)
            else:
                self.pubsub.publish(HathorEvents.STORAGE_TX_VOIDED, tx=tx)

        if self.with_index and add_to_indexes:
            self.add_to_indexes(tx)

    @abstractmethod
    def remove_transaction(self, tx: BaseTransaction) -> None:
        """Remove the tx.

        :param tx: Trasaction to be removed
        """
        if self.with_index:
            self.del_from_indexes(tx, remove_all=True, relax_assert=True)

    @abstractmethod
    def transaction_exists(self, hash_bytes: bytes) -> bool:
        """Returns `True` if transaction with hash `hash_bytes` exists.

        :param hash_bytes: Hash in bytes that will be checked.
        """
        raise NotImplementedError

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
        return tx

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

    @abstractmethod
    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        # TODO: verify the following claim:
        """Return all transactions that are not blocks.

        :rtype :py:class:`typing.Iterable[hathor.transaction.BaseTransaction]`
        """
        raise NotImplementedError

    @abstractmethod
    def get_count_tx_blocks(self) -> int:
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
    def get_best_block_tips(self, timestamp: Optional[float] = None, *, skip_cache: bool = False) -> List[bytes]:
        """ Return a list of blocks that are heads in a best chain. It must be used when mining.

        When more than one block is returned, it means that there are multiple best chains and
        you can choose any of them.
        """
        if timestamp is None and not skip_cache and self._best_block_tips_cache is not None:
            return self._best_block_tips_cache[:]

        best_score = 0.0
        best_tip_blocks: List[bytes] = []

        for block_hash in (x.data for x in self.get_block_tips(timestamp)):
            meta = self.get_metadata(block_hash)
            assert meta is not None
            if meta.voided_by and meta.voided_by != set([block_hash]):
                # If anyone but the block itself is voiding this block, then it must be skipped.
                continue
            if abs(meta.score - best_score) < 1e-10:
                best_tip_blocks.append(block_hash)
            elif meta.score > best_score:
                best_score = meta.score
                best_tip_blocks = [block_hash]
        return best_tip_blocks

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
            head_height = head.get_metadata().height
            if head_height > highest_height:
                highest_height = head_height

        return highest_height

    def get_merkle_tree(self, timestamp: int) -> Tuple[bytes, List[bytes]]:
        """ Generate a hash to check whether the DAG is the same at that timestamp.

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        if self._all_tips_cache is not None and timestamp >= self._all_tips_cache.timestamp:
            return self._all_tips_cache.merkle_tree, self._all_tips_cache.hashes

        intervals = self.get_all_tips(timestamp)
        if timestamp >= self.latest_timestamp:
            # get_all_tips will add to cache in that case
            assert self._all_tips_cache is not None
            return self._all_tips_cache.merkle_tree, self._all_tips_cache.hashes

        return self.calculate_merkle_tree(intervals)

    def calculate_merkle_tree(self, intervals: Set[Interval]) -> Tuple[bytes, List[bytes]]:
        """ Generate a hash of the transactions at the intervals

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        hashes = [x.data for x in intervals]
        hashes.sort()

        merkle = hashlib.sha256()
        for h in hashes:
            merkle.update(h)

        return merkle.digest(), hashes

    @abstractmethod
    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_all_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_newest_blocks(self, count: int) -> Tuple[List[Block], bool]:
        """ Get blocks from the newest to the oldest

        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest_txs(self, count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get transactions from the newest to the oldest

        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[Block], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of blocks to be returned
        :return: List of blocks and a boolean indicating if has more blocks
        """
        raise NotImplementedError

    @abstractmethod
    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        """ Get transactions from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions to be returned
        :return: List of transactions and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
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

    @abstractmethod
    def _topological_sort(self) -> Iterator[BaseTransaction]:
        """Return an iterable of the transactions in topological ordering, i.e., from
        genesis to the most recent transactions. The order is important because the
        transactions are always valid---their parents and inputs exist.

        :return: An iterable with the sorted transactions
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
    def get_all_genesis(self) -> Set[BaseTransaction]:
        raise NotImplementedError

    @abstractmethod
    def get_transactions_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[BaseTransaction]:
        """Run a BFS starting from the giving `hash_bytes`.

        :param hash_bytes: Starting point of the BFS, either a block or a transaction.
        :param num_blocks: Number of blocks to be return.
        :return: List of transactions
        """
        raise NotImplementedError

    @abstractmethod
    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[Block]:
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

    def start_full_verification(self) -> None:
        """ Save full verification on storage
        """
        self.add_value(self._running_full_verification_attribute, '1')

    def finish_full_verification(self) -> None:
        """ Remove from storage that the full node is initializing with a full verification
        """
        self.remove_value(self._running_full_verification_attribute)

    def is_running_full_verification(self) -> bool:
        """ Return if the full node is initializing with a full verification
            or was running a full verification and was stopped in the middle
        """
        return self.get_value(self._running_full_verification_attribute) == '1'

    def start_running_manager(self) -> None:
        """ Save on storage that manager is running
        """
        self.add_value(self._manager_running_attribute, '1')

    def stop_running_manager(self) -> None:
        """ Remove from storage that manager is running
        """
        self.remove_value(self._manager_running_attribute)

    def is_running_manager(self) -> bool:
        """ Return if the manager is running or was running and a sudden crash stopped the full node
        """
        return self.get_value(self._manager_running_attribute) == '1'


class BaseTransactionStorage(TransactionStorage):
    def __init__(self, with_index: bool = True, pubsub: Optional[Any] = None) -> None:
        super().__init__()

        # Pubsub is used to publish tx voided and winner but it's optional
        self.pubsub = pubsub

        # Initialize index if needed.
        self.with_index = with_index
        if with_index:
            self._reset_cache()

        # Either save or verify all genesis.
        self._save_or_verify_genesis()

    @property
    def latest_timestamp(self) -> int:
        return self._latest_timestamp

    @property
    def first_timestamp(self) -> int:
        return self._first_timestamp

    @abstractmethod
    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        raise NotImplementedError

    def _build_indexes_manager(self) -> IndexesManager:
        return MemoryIndexesManager()

    def _reset_cache(self) -> None:
        """Reset all caches. This function should not be called unless you know what you are doing."""
        assert self.with_index, 'Cannot reset cache because it has not been enabled.'
        self._cache_block_count = 0
        self._cache_tx_count = 0

        self.indexes = self._build_indexes_manager()

        genesis = self.get_all_genesis()
        if genesis:
            self._latest_timestamp = max(x.timestamp for x in genesis)
            self._first_timestamp = min(x.timestamp for x in genesis)
        else:
            self._latest_timestamp = 0
            self._first_timestamp = 0

    def remove_cache(self) -> None:
        """Remove all caches in case we don't need it."""
        self.with_index = False
        self.indexes = None

    def get_best_block_tips(self, timestamp: Optional[float] = None, *, skip_cache: bool = False) -> List[bytes]:
        return super().get_best_block_tips(timestamp, skip_cache=skip_cache)

    def get_weight_best_block(self) -> float:
        return super().get_weight_best_block()

    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        if timestamp is None:
            timestamp = self.latest_timestamp
        return self.indexes.block_tips[timestamp]

    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
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

    def get_all_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
        if not self.with_index:
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

    def get_newest_blocks(self, count: int) -> Tuple[List[Block], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_newest(count)
        blocks = [cast(Block, self.get_transaction(block_hash)) for block_hash in block_hashes]
        return blocks, has_more

    def get_newest_txs(self, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_newest(count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[Block], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_older(timestamp, hash_bytes, count)
        blocks = [cast(Block, self.get_transaction(block_hash)) for block_hash in block_hashes]
        return blocks, has_more

    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        block_hashes, has_more = self.indexes.sorted_blocks.get_newer(timestamp, hash_bytes, count)
        blocks = [self.get_transaction(block_hash) for block_hash in block_hashes]
        return blocks, has_more

    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_older(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes, count: int) -> Tuple[List[BaseTransaction], bool]:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        tx_hashes, has_more = self.indexes.sorted_txs.get_newer(timestamp, hash_bytes, count)
        txs = [self.get_transaction(tx_hash) for tx_hash in tx_hashes]
        return txs, has_more

    def _manually_initialize(self) -> None:
        self._reset_cache()

        # We need to construct a topological sort, then iterate from
        # genesis to tips.
        for tx in self._topological_sort():
            self.add_to_indexes(tx)

    def _topological_sort(self) -> Iterator[BaseTransaction]:
        # TODO We must optimize this algorithm to remove the `visited` set.
        #      It will consume too much memory when the number of transactions is big.
        #      A solution would be to store the ordering in disk, probably indexing by tx's height.
        #      Sorting the vertices by the lengths of their longest incoming paths produces a topological
        #      ordering (Dekel, Nassimi & Sahni 1981). See: https://epubs.siam.org/doi/10.1137/0210049
        #      See also: https://gitlab.com/HathorNetwork/hathor-python/merge_requests/31
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        for tx in self.get_all_transactions():
            if not tx.is_block:
                continue
            yield from self._topological_sort_dfs(tx, visited)
        for tx in self.get_all_transactions():
            yield from self._topological_sort_dfs(tx, visited)

    def _topological_sort_dfs(self, root: BaseTransaction, visited: Dict[bytes, int]) -> Iterator[BaseTransaction]:
        if root.hash in visited:
            return

        stack = [root]
        while stack:
            tx = stack[-1]
            assert tx.hash is not None
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
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        self._latest_timestamp = max(self.latest_timestamp, tx.timestamp)
        if self._first_timestamp == 0:
            self._first_timestamp = tx.timestamp
        else:
            self._first_timestamp = min(self.first_timestamp, tx.timestamp)
        self._first_timestamp = min(self.first_timestamp, tx.timestamp)
        self._all_tips_cache = None

        success = self.indexes.add_tx(tx)

        if success:
            if tx.is_block:
                self._cache_block_count += 1
            else:
                self._cache_tx_count += 1

    def del_from_indexes(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        self.indexes.del_tx(tx, remove_all=remove_all, relax_assert=relax_assert)
        if tx.is_block:
            self._cache_block_count -= 1
        else:
            self._cache_tx_count -= 1

    def get_block_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        return self._cache_block_count

    def get_tx_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        return self._cache_tx_count

    def get_genesis(self, hash_bytes: bytes) -> Optional[BaseTransaction]:
        assert self._genesis_cache is not None
        return self._genesis_cache.get(hash_bytes, None)

    def get_all_genesis(self) -> Set[BaseTransaction]:
        assert self._genesis_cache is not None
        return set(self._genesis_cache.values())

    def get_transactions_before(self, hash_bytes: bytes,
                                num_blocks: int = 100) -> List[BaseTransaction]:  # pragma: no cover
        ref_tx = self.get_transaction(hash_bytes)
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        result = [x for x in self._topological_sort_dfs(ref_tx, visited) if not x.is_block]
        result = result[-num_blocks:]
        return result

    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[Block]:
        ref_tx = self.get_transaction(hash_bytes)
        if not ref_tx.is_block:
            raise TransactionIsNotABlock
        result = []  # List[Block]
        pending_visits = deque(ref_tx.parents)  # List[bytes]
        used = set(pending_visits)  # Set[bytes]
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
