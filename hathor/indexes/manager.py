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
from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.indexes.address_index import AddressIndex
from hathor.indexes.deps_index import DepsIndex
from hathor.indexes.height_index import HeightIndex
from hathor.indexes.mempool_tips_index import MempoolTipsIndex
from hathor.indexes.timestamp_index import TimestampIndex
from hathor.indexes.tips_index import TipsIndex
from hathor.indexes.tokens_index import TokensIndex
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.pubsub import PubSubManager
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class IndexesManager(ABC):
    """ IndexesManager manages all the indexes that we will have in the system

    The idea is for the manager to handle all method calls to indexes,
    so it will know which index is better to use in each moment
    """

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

    @abstractmethod
    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        """Enable address index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_tokens_index(self) -> None:
        """Enable tokens index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    def _manually_initialize_tips_indexes(self, tx_storage: 'TransactionStorage') -> None:
        """ Initialize the tips indexes, populating them from a tx_storage that is otherwise complete.

        XXX: this method requires timestamp indexes to be complete and up-to-date with the rest of the database
        XXX: this method is not yet being used
        """
        for tx in tx_storage._topological_sort_timestamp_index():
            tx_meta = tx.get_metadata()
            if not tx_meta.validation.is_final():
                continue

            self.all_tips.add_tx(tx)

            if tx.is_block:
                self.block_tips.add_tx(tx)
            elif not tx_meta.voided_by:
                self.tx_tips.add_tx(tx)

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

        if tx.is_block:
            self.block_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_blocks.del_tx(tx)
        else:
            self.tx_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_txs.del_tx(tx)

        if self.tokens:
            self.tokens.del_tx(tx)

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
        self.height = MemoryHeightIndex()
        self.mempool_tips = MemoryMempoolTipsIndex()
        self.deps = MemoryDepsIndex()

    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        from hathor.indexes.memory_address_index import MemoryAddressIndex
        if self.addresses is None:
            self.addresses = MemoryAddressIndex(pubsub)

    def enable_tokens_index(self) -> None:
        from hathor.indexes.memory_tokens_index import MemoryTokensIndex
        if self.tokens is None:
            self.tokens = MemoryTokensIndex()


class RocksDBIndexesManager(IndexesManager):
    def __init__(self, db: 'rocksdb.DB') -> None:
        from hathor.indexes.memory_deps_index import MemoryDepsIndex
        from hathor.indexes.rocksdb_height_index import RocksDBHeightIndex
        from hathor.indexes.rocksdb_mempool_tips_index import RocksDBMempoolTipsIndex
        from hathor.indexes.rocksdb_timestamp_index import RocksDBTimestampIndex

        self._db = db

        self.all_tips = TipsIndex()
        self.block_tips = TipsIndex()
        self.tx_tips = TipsIndex()

        self.sorted_all = RocksDBTimestampIndex(self._db, cf_name=b'timestamp-sorted-all')
        self.sorted_blocks = RocksDBTimestampIndex(self._db, cf_name=b'timestamp-sorted-blocks')
        self.sorted_txs = RocksDBTimestampIndex(self._db, cf_name=b'timestamp-sorted-txs')

        self.addresses = None
        self.tokens = None
        self.height = RocksDBHeightIndex(self._db)
        self.mempool_tips = RocksDBMempoolTipsIndex(self._db)
        self.deps = MemoryDepsIndex()  # use of RocksDBDepsIndex is currently suspended until it is fixed

    def enable_address_index(self, pubsub: 'PubSubManager') -> None:
        from hathor.indexes.rocksdb_address_index import RocksDBAddressIndex
        if self.addresses is None:
            self.addresses = RocksDBAddressIndex(self._db, pubsub=pubsub)

    def enable_tokens_index(self) -> None:
        from hathor.indexes.rocksdb_tokens_index import RocksDBTokensIndex
        if self.tokens is None:
            self.tokens = RocksDBTokensIndex(self._db)
