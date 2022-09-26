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
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple, cast
from weakref import WeakValueDictionary

from intervaltree.interval import Interval
from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.indexes import IndexesManager, MemoryIndexesManager
from hathor.pubsub import PubSubManager
from hathor.transaction.base_transaction import BaseTransaction
from hathor.transaction.block import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionIsNotABlock
from hathor.transaction.transaction import Transaction
from hathor.transaction.transaction_metadata import TransactionMetadata

settings = HathorSettings()

# these are the timestamp values to be used when resetting them, 1 is used for the node instead of 0, so it can be
# greater, that way if both are reset (which also happens on a database that never run this implementation before) we
# guarantee that indexes will be initialized (because they would be "older" than the node timestamp).
NULL_INDEX_LAST_STARTED_AT = 0
NULL_LAST_STARTED_AT = 1
INDEX_ATTR_PREFIX = 'index_'


class AllTipsCache(NamedTuple):
    timestamp: int
    tips: Set[Interval]
    merkle_tree: bytes
    hashes: List[bytes]


class TransactionStorage(ABC):
    """Legacy sync interface, please copy @deprecated decorator when implementing methods."""

    pubsub: Optional[PubSubManager]
    with_index: bool
    indexes: Optional[IndexesManager]

    log = get_logger()

    # Key storage attribute to save if the network stored is the expected network
    _network_attribute: str = 'network'

    # Key storage attribute to save if the full node is running a full verification
    _running_full_verification_attribute: str = 'running_full_verification'

    # Key storage attribute to save if the manager is running
    _manager_running_attribute: str = 'manager_running'

    # Ket storage attribute to save the last time the node started
    _last_start_attribute: str = 'last_start'

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

        # Internal toggle to choose when to select topological DFS iterator, used only on some tests
        self._always_use_topological_dfs = False

        # Only used in self.add_to_indexes to bypass raising an exception
        self._saving_genesis = False

    @abstractmethod
    def reset_indexes(self) -> None:
        """Reset all the indexes, making sure that no persisted value is reused."""
        raise NotImplementedError

    def update_best_block_tips_cache(self, tips_cache: Optional[List[bytes]]) -> None:
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
        self._saving_genesis = True
        for tx in self._get_genesis_from_settings():
            try:
                assert tx.hash is not None
                tx2 = self.get_transaction(tx.hash)
                assert tx == tx2
            except TransactionDoesNotExist:
                self.save_transaction(tx)
                self.add_to_indexes(tx)
                tx2 = tx
            assert tx2.hash is not None
            self._genesis_cache[tx2.hash] = tx2
        self._saving_genesis = False

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
    def save_transaction(self: 'TransactionStorage', tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        # XXX: although this method is abstract (because a subclass must implement it) the implementer
        #      should call the base implementation for correctly interacting with the index
        """Saves the tx.

        :param tx: Transaction to save
        :param only_metadata: Don't save the transaction, only the metadata of this transaction
        """
        assert tx.hash is not None
        meta = tx.get_metadata()

        # XXX: we can only add to cache and publish txs that are fully connected (which also implies it's valid)
        if not meta.validation.is_fully_connected():
            return

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

    def compare_bytes_with_local_tx(self, tx: BaseTransaction) -> bool:
        """Compare byte-per-byte `tx` with the local transaction."""
        assert tx.hash is not None
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
        if timestamp is None:
            self._best_block_tips_cache = best_tip_blocks[:]
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
            iter_tx = self._topological_sort_timestamp_index()
        else:
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


class BaseTransactionStorage(TransactionStorage):
    def __init__(self, with_index: bool = True, pubsub: Optional[Any] = None) -> None:
        super().__init__()

        # Pubsub is used to publish tx voided and winner but it's optional
        self.pubsub = pubsub

        # Initialize index if needed.
        self.with_index = with_index
        if with_index:
            self.indexes = self._build_indexes_manager()

        # Either save or verify all genesis.
        self._save_or_verify_genesis()

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

    def _build_indexes_manager(self) -> IndexesManager:
        return MemoryIndexesManager()

    def reset_indexes(self) -> None:
        """Reset all indexes. This function should not be called unless you know what you are doing."""
        assert self.with_index, 'Cannot reset indexes because they have not been enabled.'
        assert self.indexes is not None
        self.indexes.force_clear_all()

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
        self._manually_initialize_indexes()

    def _manually_initialize_indexes(self) -> None:
        if self.indexes is not None:
            self.indexes._manually_initialize(self)

    def _topological_sort_timestamp_index(self) -> Iterator[BaseTransaction]:
        assert self.indexes is not None

        cur_timestamp: Optional[int] = None
        cur_blocks: List[Block] = []
        cur_txs: List[Transaction] = []
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

    def _topological_sort_metadata(self) -> Iterator[BaseTransaction]:
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

        to_visit: List[Item] = list(map(Item, self.get_all_genesis()))
        seen: Set[bytes] = set()
        heapq.heapify(to_visit)
        while to_visit:
            item = heapq.heappop(to_visit)
            assert item.tx.hash is not None
            yield item.tx
            # XXX: We can safely discard because no other tx will try to visit this one, since timestamps are strictly
            #      higher in children, meaning we cannot possibly have item.tx as a descendant of any tx in to_visit.
            seen.discard(item.tx.hash)
            for child_tx_hash in item.tx.get_metadata().children:
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
        visited: Dict[bytes, int] = dict()  # Dict[bytes, int]
        for tx in self.get_all_transactions():
            if not tx.is_block:
                continue
            yield from self._run_topological_sort_dfs(tx, visited)
        for tx in self.get_all_transactions():
            yield from self._run_topological_sort_dfs(tx, visited)

    def _run_topological_sort_dfs(self, root: BaseTransaction, visited: Dict[bytes, int]) -> Iterator[BaseTransaction]:
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
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        self.indexes.del_tx(tx, remove_all=remove_all, relax_assert=relax_assert)

    def get_block_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        return self.indexes.info.get_block_count()

    def get_tx_count(self) -> int:
        if not self.with_index:
            raise NotImplementedError
        assert self.indexes is not None
        return self.indexes.info.get_tx_count()

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
        result = [x for x in self._run_topological_sort_dfs(ref_tx, visited) if not x.is_block]
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

    def flush(self) -> None:
        pass
