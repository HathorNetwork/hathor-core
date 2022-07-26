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

from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import TYPE_CHECKING, Iterator, List, Optional, Tuple

from structlog import get_logger

from hathor.indexes.address_index import AddressIndex
from hathor.indexes.base_index import BaseIndex
from hathor.indexes.deps_index import DepsIndex
from hathor.indexes.height_index import HeightIndex
from hathor.indexes.mempool_tips_index import MempoolTipsIndex
from hathor.indexes.timestamp_index import TimestampIndex
from hathor.indexes.tips_index import TipsIndex
from hathor.indexes.tokens_index import TokensIndex
from hathor.indexes.utxo_index import UtxoIndex
from hathor.transaction import BaseTransaction
from hathor.util import progress

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.pubsub import PubSubManager
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class _IndexFilter(Enum):
    ALL = auto()  # block or tx, voided or not
    ALL_BLOCKS = auto()  # only blocks that are not voided
    VALID_TXS = auto()  # only transactions that are not voided


class IndexesManager(ABC):
    """ IndexesManager manages all the indexes that we will have in the system

    The idea is for the manager to handle all method calls to indexes,
    so it will know which index is better to use in each moment
    """

    log = get_logger()

    all_tips: TipsIndex
    block_tips: TipsIndex
    tx_tips: TipsIndex

    sorted_all: TimestampIndex
    sorted_blocks: TimestampIndex
    sorted_txs: TimestampIndex

    deps: DepsIndex
    height: HeightIndex
    mempool_tips: MempoolTipsIndex
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
        for _, index in self._iter_all_indexes_with_filter():
            yield index

    def _iter_all_indexes_with_filter(self) -> Iterator[Tuple[_IndexFilter, BaseIndex]]:
        """ Same as `iter_all_indexes()`, but includes a filter for what transactions an index is interested in."""
        yield _IndexFilter.ALL, self.all_tips
        yield _IndexFilter.ALL_BLOCKS, self.block_tips
        yield _IndexFilter.VALID_TXS, self.tx_tips
        yield _IndexFilter.ALL, self.sorted_all
        yield _IndexFilter.ALL_BLOCKS, self.sorted_blocks
        yield _IndexFilter.VALID_TXS, self.sorted_txs
        yield _IndexFilter.ALL, self.deps
        yield _IndexFilter.ALL, self.height
        yield _IndexFilter.ALL, self.mempool_tips
        if self.addresses is not None:
            yield _IndexFilter.ALL, self.addresses
        if self.tokens is not None:
            yield _IndexFilter.ALL, self.tokens
        if self.utxo is not None:
            yield _IndexFilter.ALL, self.utxo

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

    def force_clear_all(self) -> None:
        """ Force clear all indexes.
        """
        for index in self.iter_all_indexes():
            index.force_clear()

    def _manually_initialize(self, tx_storage: 'TransactionStorage') -> None:
        """ Initialize the indexes, checking the indexes that need initialization, and the optimal iterator to use.
        """
        from hathor.transaction.genesis import BLOCK_GENESIS
        from hathor.transaction.storage.transaction_storage import NULL_INDEX_LAST_STARTED_AT

        db_last_started_at = tx_storage.get_last_started_at()

        indexes_to_init: List[Tuple[_IndexFilter, BaseIndex]] = []
        for index_filter, index in self._iter_all_indexes_with_filter():
            index_db_name = index.get_db_name()
            if index_db_name is None:
                indexes_to_init.append((index_filter, index))
                continue
            index_last_started_at = tx_storage.get_index_last_started_at(index_db_name)
            if db_last_started_at != index_last_started_at:
                indexes_to_init.append((index_filter, index))

        if indexes_to_init:
            self.log.debug('there are indexes that need initialization',
                           indexes_to_init=[i for _, i in indexes_to_init])
        else:
            self.log.debug('there are no indexes that need initialization')

        # make sure that all the indexes that we're rebuilding are cleared
        for _, index in indexes_to_init:
            index_db_name = index.get_db_name()
            if index_db_name:
                tx_storage.set_index_last_started_at(index_db_name, NULL_INDEX_LAST_STARTED_AT)
            index.force_clear()

        block_count = 0
        tx_count = 0
        latest_timestamp = BLOCK_GENESIS.timestamp
        first_timestamp = BLOCK_GENESIS.timestamp
        total = tx_storage.get_count_tx_blocks()

        for tx in progress(tx_storage.topological_iterator(), log=self.log, total=total):
            # XXX: these would probably make more sense to be their own simple "indexes" instead of how it is here
            latest_timestamp = max(tx.timestamp, latest_timestamp)
            first_timestamp = min(tx.timestamp, first_timestamp)
            if tx.is_block:
                block_count += 1
            else:
                tx_count += 1

            tx_meta = tx.get_metadata()

            # feed each transaction to the indexes that they are interested in
            for index_filter, index in indexes_to_init:
                if index_filter is _IndexFilter.ALL:
                    index.init_loop_step(tx)
                elif index_filter is _IndexFilter.ALL_BLOCKS:
                    if tx.is_block:
                        index.init_loop_step(tx)
                elif index_filter is _IndexFilter.VALID_TXS:
                    # XXX: all indexes that use this filter treat soft-voided as voided, nothing special needed
                    if tx.is_transaction and not tx_meta.voided_by:
                        index.init_loop_step(tx)
                else:
                    assert False, 'impossible filter'

        tx_storage._update_caches(block_count, tx_count, latest_timestamp, first_timestamp)

    def update(self, tx: BaseTransaction) -> None:
        """ This is the new update method that indexes should use instead of add_tx/del_tx
        """
        # XXX: this _should_ be here, but it breaks some tests, for now this is done explicitly in hathor.manager
        # self.mempool_tips.update(tx)
        self.deps.update(tx)
        if self.utxo:
            self.utxo.update(tx)

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        # These two calls return False when a transaction changes from
        # voided to executed and vice-versa.
        r1 = self.all_tips.add_tx(tx)
        r2 = self.sorted_all.add_tx(tx)
        assert r1 == r2

        if tx.is_block:
            r3 = self.block_tips.add_tx(tx)
            r4 = self.sorted_blocks.add_tx(tx)
            assert r3 == r4
        else:
            r3 = self.tx_tips.add_tx(tx)
            r4 = self.sorted_txs.add_tx(tx)
            assert r3 == r4

        if self.addresses:
            self.addresses.add_tx(tx)
        if self.tokens:
            self.tokens.add_tx(tx)

        # XXX: this method is idempotent and has no result
        self.deps.add_tx(tx)

        return r3

    def del_tx(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        if remove_all:
            # We delete from indexes in two cases: (i) mark tx as voided, and (ii) remove tx.
            # We only remove tx from all_tips and sorted_all when it is removed from the storage.
            # For clarity, when a tx is marked as voided, it is not removed from all_tips and sorted_all.
            self.all_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_all.del_tx(tx)
            if self.addresses:
                self.addresses.remove_tx(tx)
            if self.utxo:
                self.utxo.del_tx(tx)

        if tx.is_block:
            self.block_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_blocks.del_tx(tx)
        else:
            self.tx_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_txs.del_tx(tx)

        if self.tokens:
            self.tokens.del_tx(tx)

        # XXX: this method is idempotent and has no result
        self.deps.del_tx(tx)


class MemoryIndexesManager(IndexesManager):
    def __init__(self) -> None:
        from hathor.indexes.memory_deps_index import MemoryDepsIndex
        from hathor.indexes.memory_height_index import MemoryHeightIndex
        from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
        from hathor.indexes.memory_timestamp_index import MemoryTimestampIndex

        self.all_tips = TipsIndex()
        self.block_tips = TipsIndex()
        self.tx_tips = TipsIndex()

        self.sorted_all = MemoryTimestampIndex()
        self.sorted_blocks = MemoryTimestampIndex()
        self.sorted_txs = MemoryTimestampIndex()

        self.addresses = None
        self.tokens = None
        self.utxo = None
        self.height = MemoryHeightIndex()
        self.mempool_tips = MemoryMempoolTipsIndex()
        self.deps = MemoryDepsIndex()

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


class RocksDBIndexesManager(IndexesManager):
    def __init__(self, db: 'rocksdb.DB') -> None:
        from hathor.indexes.memory_deps_index import MemoryDepsIndex
        from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
        from hathor.indexes.rocksdb_height_index import RocksDBHeightIndex
        from hathor.indexes.rocksdb_timestamp_index import RocksDBTimestampIndex

        self._db = db

        self.all_tips = TipsIndex()
        self.block_tips = TipsIndex()
        self.tx_tips = TipsIndex()

        self.sorted_all = RocksDBTimestampIndex(self._db, 'all')
        self.sorted_blocks = RocksDBTimestampIndex(self._db, 'blocks')
        self.sorted_txs = RocksDBTimestampIndex(self._db, 'txs')

        self.addresses = None
        self.tokens = None
        self.utxo = None
        self.height = RocksDBHeightIndex(self._db)
        self.mempool_tips = MemoryMempoolTipsIndex()  # use of RocksDBMempoolTipsIndex is very slow and was suspended
        self.deps = MemoryDepsIndex()  # use of RocksDBDepsIndex is currently suspended until it is fixed

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
