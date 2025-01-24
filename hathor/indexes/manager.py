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

import operator
from abc import ABC, abstractmethod
from functools import reduce
from typing import TYPE_CHECKING, Iterator, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.address_index import AddressIndex
from hathor.indexes.base_index import BaseIndex
from hathor.indexes.height_index import HeightIndex
from hathor.indexes.info_index import InfoIndex
from hathor.indexes.mempool_tips_index import MempoolTipsIndex
from hathor.indexes.timestamp_index import ScopeType as TimestampScopeType, TimestampIndex
from hathor.indexes.tokens_index import TokensIndex
from hathor.indexes.utxo_index import UtxoIndex
from hathor.transaction import BaseTransaction
from hathor.util import tx_progress

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import PubSubManager
    from hathor.storage import RocksDBStorage
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()

MAX_CACHE_SIZE_DURING_LOAD = 1000


class IndexesManager(ABC):
    """ IndexesManager manages all the indexes that we will have in the system

    The idea is for the manager to handle all method calls to indexes,
    so it will know which index is better to use in each moment
    """

    log = get_logger()

    info: InfoIndex

    sorted_all: TimestampIndex
    sorted_blocks: TimestampIndex
    sorted_txs: TimestampIndex

    height: HeightIndex
    mempool_tips: Optional[MempoolTipsIndex]
    addresses: Optional[AddressIndex]
    tokens: Optional[TokensIndex]
    utxo: Optional[UtxoIndex]

    def __init_checks__(self):
        """ Implementations must call this at the **end** of their __init__ for running ValueError checks."""
        # check if every index has a unique db_name
        indexes_db_names = set()
        for index in self.iter_all_indexes():
            index_db_name = index.get_db_name()
            if index_db_name is None:
                continue
            if index_db_name in indexes_db_names:
                raise ValueError(f'duplicate index name "{index_db_name}", already in use by another index')
            indexes_db_names.add(index_db_name)

    def iter_all_indexes(self) -> Iterator[BaseIndex]:
        """ Iterate over all of the indexes abstracted by this manager, hiding their specific implementation details"""
        return filter(None, [
            self.info,
            self.sorted_all,
            self.sorted_blocks,
            self.sorted_txs,
            self.height,
            self.mempool_tips,
            self.addresses,
            self.tokens,
            self.utxo,
        ])

    @abstractmethod
    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        """Enable address index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_tokens_index(self) -> None:
        """Enable tokens index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_utxo_index(self) -> None:
        """Enable UTXO index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_mempool_index(self) -> None:
        """Enable mempool index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    def force_clear_all(self) -> None:
        """ Force clear all indexes.
        """
        for index in self.iter_all_indexes():
            index.force_clear()

    def _manually_initialize(self, tx_storage: 'TransactionStorage') -> None:
        """ Initialize the indexes, checking the indexes that need initialization, and the optimal iterator to use.
        """
        from hathor.transaction.storage.transaction_storage import NULL_INDEX_LAST_STARTED_AT

        db_last_started_at = tx_storage.get_last_started_at()

        indexes_to_init: list[BaseIndex] = []
        for index in self.iter_all_indexes():
            index_db_name = index.get_db_name()
            if index_db_name is None:
                indexes_to_init.append(index)
                continue
            index_last_started_at = tx_storage.get_index_last_started_at(index_db_name)
            if db_last_started_at != index_last_started_at:
                indexes_to_init.append(index)

        if indexes_to_init:
            self.log.info('there are indexes that need initialization', indexes_to_init=indexes_to_init)
        else:
            self.log.info('there are no indexes that need initialization')

        # make sure that all the indexes that we're rebuilding are cleared
        for index in indexes_to_init:
            index_db_name = index.get_db_name()
            if index_db_name:
                tx_storage.set_index_last_started_at(index_db_name, NULL_INDEX_LAST_STARTED_AT)
            index.force_clear()

        cache_capacity = None

        # Reduce cache size during initialization.
        from hathor.transaction.storage import TransactionCacheStorage
        if isinstance(tx_storage, TransactionCacheStorage):
            cache_capacity = tx_storage.capacity
            tx_storage.set_capacity(min(MAX_CACHE_SIZE_DURING_LOAD, cache_capacity))

        self.log.debug('indexes pre-init')
        for index in self.iter_all_indexes():
            index.init_start(self)

        if indexes_to_init:
            overall_scope = reduce(operator.__or__, map(lambda i: i.get_scope(), indexes_to_init))
            tx_iter_inner = overall_scope.get_iterator(tx_storage)
            tx_iter = tx_progress(tx_iter_inner, log=self.log, total=tx_storage.get_vertices_count())
            self.log.debug('indexes init', scope=overall_scope)
        else:
            tx_iter = iter([])
            self.log.debug('indexes init')

        for tx in tx_iter:
            # feed each transaction to the indexes that they are interested in
            for index in indexes_to_init:
                if index.get_scope().matches(tx):
                    index.init_loop_step(tx)

        # Restore cache capacity.
        if isinstance(tx_storage, TransactionCacheStorage):
            assert cache_capacity is not None
            tx_storage.set_capacity(cache_capacity)

    def update(self, tx: BaseTransaction) -> None:
        """ This is the new update method that indexes should use instead of add_tx/del_tx
        """
        # XXX: this _should_ be here, but it breaks some tests, for now this is done explicitly in hathor.manager
        # self.mempool_tips.update(tx)
        if self.utxo:
            self.utxo.update(tx)

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        self.info.update_timestamps(tx)

        r1 = self.sorted_all.add_tx(tx)

        if tx.is_block:
            r2 = self.sorted_blocks.add_tx(tx)
        else:
            r2 = self.sorted_txs.add_tx(tx)

        if self.addresses:
            self.addresses.add_tx(tx)
        if self.tokens:
            self.tokens.add_tx(tx)

        # We need to check r1 as well to make sure we don't count twice the transactions/blocks that are
        # just changing from voided to executed or vice-versa
        if r1:
            self.info.update_counts(tx)

        return r2

    def del_tx(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        assert tx.storage is not None

        if remove_all:
            # We delete from indexes in two cases: (i) mark tx as voided, and (ii) remove tx.
            # We only remove tx from sorted_all when it is removed from the storage.
            # For clarity, when a tx is marked as voided, it is not removed from sorted_all.
            self.sorted_all.del_tx(tx)
            if self.addresses:
                self.addresses.remove_tx(tx)
            if self.utxo:
                self.utxo.del_tx(tx)
            self.info.update_counts(tx, remove=True)

        # mempool will pick-up if the transaction is voided/invalid and remove it
        if self.mempool_tips is not None and tx.storage.transaction_exists(tx.hash):
            logger.debug('remove from mempool tips', tx=tx.hash_hex)
            self.mempool_tips.update(tx, remove=True)

        if tx.is_block:
            self.sorted_blocks.del_tx(tx)
        else:
            self.sorted_txs.del_tx(tx)

        if self.tokens:
            self.tokens.del_tx(tx)


class MemoryIndexesManager(IndexesManager):
    def __init__(self, *, settings: HathorSettings | None = None) -> None:
        from hathor.indexes.memory_height_index import MemoryHeightIndex
        from hathor.indexes.memory_info_index import MemoryInfoIndex
        from hathor.indexes.memory_timestamp_index import MemoryTimestampIndex

        self.info = MemoryInfoIndex()

        self.sorted_all = MemoryTimestampIndex(scope_type=TimestampScopeType.ALL)
        self.sorted_blocks = MemoryTimestampIndex(scope_type=TimestampScopeType.BLOCKS)
        self.sorted_txs = MemoryTimestampIndex(scope_type=TimestampScopeType.TXS)

        self.addresses = None
        self.tokens = None
        self.utxo = None
        self.height = MemoryHeightIndex(settings=settings)
        self.mempool_tips = None

        # XXX: this has to be at the end of __init__, after everything has been initialized
        self.__init_checks__()

    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        from hathor.indexes.memory_address_index import MemoryAddressIndex
        if self.addresses is None:
            self.addresses = MemoryAddressIndex(pubsub)

    def enable_tokens_index(self) -> None:
        from hathor.indexes.memory_tokens_index import MemoryTokensIndex
        if self.tokens is None:
            self.tokens = MemoryTokensIndex()

    def enable_utxo_index(self) -> None:
        from hathor.indexes.memory_utxo_index import MemoryUtxoIndex
        if self.utxo is None:
            self.utxo = MemoryUtxoIndex()

    def enable_mempool_index(self) -> None:
        from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
        if self.mempool_tips is None:
            self.mempool_tips = MemoryMempoolTipsIndex()


class RocksDBIndexesManager(IndexesManager):
    def __init__(self, rocksdb_storage: 'RocksDBStorage') -> None:
        from hathor.indexes.rocksdb_height_index import RocksDBHeightIndex
        from hathor.indexes.rocksdb_info_index import RocksDBInfoIndex
        from hathor.indexes.rocksdb_timestamp_index import RocksDBTimestampIndex

        self._db = rocksdb_storage.get_db()

        self.info = RocksDBInfoIndex(self._db)
        self.height = RocksDBHeightIndex(self._db)

        self.sorted_all = RocksDBTimestampIndex(self._db, scope_type=TimestampScopeType.ALL)
        self.sorted_blocks = RocksDBTimestampIndex(self._db, scope_type=TimestampScopeType.BLOCKS)
        self.sorted_txs = RocksDBTimestampIndex(self._db, scope_type=TimestampScopeType.TXS)

        self.addresses = None
        self.tokens = None
        self.utxo = None
        self.mempool_tips = None

        # XXX: this has to be at the end of __init__, after everything has been initialized
        self.__init_checks__()

    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        from hathor.indexes.rocksdb_address_index import RocksDBAddressIndex
        if self.addresses is None:
            self.addresses = RocksDBAddressIndex(self._db, pubsub=pubsub)

    def enable_tokens_index(self) -> None:
        from hathor.indexes.rocksdb_tokens_index import RocksDBTokensIndex
        if self.tokens is None:
            self.tokens = RocksDBTokensIndex(self._db)

    def enable_utxo_index(self) -> None:
        from hathor.indexes.rocksdb_utxo_index import RocksDBUtxoIndex
        if self.utxo is None:
            self.utxo = RocksDBUtxoIndex(self._db)

    def enable_mempool_index(self) -> None:
        from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
        if self.mempool_tips is None:
            # XXX: use of RocksDBMempoolTipsIndex is very slow and was suspended
            self.mempool_tips = MemoryMempoolTipsIndex()
