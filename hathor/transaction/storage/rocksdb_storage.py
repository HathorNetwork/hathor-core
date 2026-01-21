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

from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Iterator, Optional

from structlog import get_logger
from twisted.internet import threads
from typing_extensions import override

from hathor.indexes import IndexesManager
from hathor.reactor import ReactorProtocol
from hathor.storage import RocksDBStorage
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.migrations import MigrationState
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, CacheConfig, CacheData
from hathor.transaction.vertex_children import RocksDBVertexChildrenService
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId
from hathor.util import json_loadb, progress

if TYPE_CHECKING:
    import rocksdb

    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.storage import NCStorageFactory
    from hathor.transaction import BaseTransaction

logger = get_logger()

_DB_NAME = 'data_v2.db'
_CF_NAME_TX = b'tx'
_CF_NAME_META = b'meta'
_CF_NAME_STATIC_META = b'static-meta'
_CF_NAME_ATTR = b'attr'
_CF_NAME_MIGRATIONS = b'migrations'


class TransactionRocksDBStorage(BaseTransactionStorage):
    """This storage saves tx and metadata to the same key on RocksDB

    It uses Protobuf serialization internally.
    """

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        rocksdb_storage: RocksDBStorage,
        settings: 'HathorSettings',
        vertex_parser: VertexParser,
        nc_storage_factory: NCStorageFactory,
        vertex_children_service: RocksDBVertexChildrenService,
        indexes: IndexesManager,
        cache_config: CacheConfig | None = None,
    ) -> None:
        self._reactor = reactor
        self._cf_tx = rocksdb_storage.get_or_create_column_family(_CF_NAME_TX)
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)
        self._cf_static_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_STATIC_META)
        self._cf_attr = rocksdb_storage.get_or_create_column_family(_CF_NAME_ATTR)
        self._cf_migrations = rocksdb_storage.get_or_create_column_family(_CF_NAME_MIGRATIONS)

        self._rocksdb_storage = rocksdb_storage
        self._db = rocksdb_storage.get_db()
        self.vertex_parser = vertex_parser

        cache_config = cache_config or CacheConfig(capacity=0)
        self.cache_data = CacheData(
            interval=cache_config.interval,
            capacity=cache_config.capacity,
            cache=OrderedDict(),
            dirty_txs=set(),
        )

        super().__init__(
            indexes=indexes,
            settings=settings,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
        )

    def pre_init(self) -> None:
        super().pre_init()
        self._reactor.callLater(self.cache_data.interval, self._start_flush_thread)

    @override
    def set_cache_capacity(self, capacity: int) -> None:
        assert capacity >= 0
        self.cache_data.capacity = capacity
        while len(self.cache_data.cache) > capacity:
            self._cache_popitem()

    def flush(self) -> None:
        self._flush_to_storage(self.cache_data.dirty_txs.copy())

    def _start_flush_thread(self) -> None:
        if self.cache_data.flush_deferred is None:
            deferred = threads.deferToThread(self._flush_to_storage, self.cache_data.dirty_txs.copy())
            deferred.addCallback(self._cb_flush_thread)
            deferred.addErrback(self._err_flush_thread)
            self.cache_data.flush_deferred = deferred

    def _cb_flush_thread(self, _res: None) -> None:
        self._reactor.callLater(self.cache_data.interval, self._start_flush_thread)
        self.cache_data.flush_deferred = None

    def _err_flush_thread(self, reason: Any) -> None:
        self.log.error('error flushing transactions', reason=reason)
        self._reactor.callLater(self.cache_data.interval, self._start_flush_thread)
        self.cache_data.flush_deferred = None

    def _flush_to_storage(self, dirty_txs_copy: set[bytes]) -> None:
        """Write dirty pages to disk."""
        for tx_hash in dirty_txs_copy:
            # a dirty tx might be removed from self.cache outside this thread: if _update_cache is called
            # and we need to save the tx to disk immediately. So it might happen that the tx which was
            # in the dirty set when the flush thread began is not in cache anymore, hence this `if` check
            if tx_hash in self.cache_data.cache:
                tx = self.cache_data.cache[tx_hash]
                self.cache_data.dirty_txs.discard(tx_hash)
                self._save_transaction_to_db(tx)

    def _cache_popitem(self) -> None:
        """Pop the last recently used cache item."""
        try:
            (_, removed_tx) = self.cache_data.cache.popitem(last=False)
        except KeyError:
            # cache is empty
            return
        if removed_tx.hash in self.cache_data.dirty_txs:
            # write to disk so we don't lose the last update
            self.cache_data.dirty_txs.discard(removed_tx.hash)
            self._save_transaction_to_db(removed_tx)

    def _update_cache(self, tx: BaseTransaction) -> None:
        """Updates the cache making sure it has at most the number of elements configured
        as its capacity.

        If we need to evict a tx from cache and it's dirty, write it to disk immediately.
        """
        _tx = self.cache_data.cache.get(tx.hash, None)
        if not _tx:
            if len(self.cache_data.cache) >= self.cache_data.capacity:
                self._cache_popitem()
            self.cache_data.cache[tx.hash] = tx
        else:
            # Tx might have been updated
            self.cache_data.cache[tx.hash] = tx
            self.cache_data.cache.move_to_end(tx.hash, last=True)

    @override
    def get_cache_data(self) -> CacheData | None:
        return self.cache_data

    def _load_from_bytes(self, tx_data: bytes, meta_data: bytes) -> 'BaseTransaction':
        from hathor.transaction.transaction_metadata import TransactionMetadata

        tx = self.vertex_parser.deserialize(tx_data)
        tx._metadata = TransactionMetadata.from_bytes(meta_data)
        tx.storage = self
        return tx

    def _tx_to_bytes(self, tx: 'BaseTransaction') -> bytes:
        return bytes(tx)

    def get_migration_state(self, migration_name: str) -> MigrationState:
        key = migration_name.encode('ascii')
        value = self._db.get((self._cf_migrations, key))
        if value is not None:
            return MigrationState.from_db_bytes(value)
        return MigrationState.NOT_STARTED

    def set_migration_state(self, migration_name: str, state: MigrationState) -> None:
        key = migration_name.encode('ascii')
        value = state.to_db_bytes()
        self._db.put((self._cf_migrations, key), value)

    def remove_transaction(self, tx: 'BaseTransaction') -> None:
        super().remove_transaction(tx)
        self.cache_data.cache.pop(tx.hash, None)
        self.cache_data.dirty_txs.discard(tx.hash)
        self._db.delete((self._cf_tx, tx.hash))
        self._db.delete((self._cf_meta, tx.hash))
        self._db.delete((self._cf_static_meta, tx.hash))
        self._remove_from_weakref(tx)

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        self._update_cache(tx)
        self.cache_data.dirty_txs.add(tx.hash)

    def _save_transaction_to_db(self, tx: 'BaseTransaction') -> None:
        key = tx.hash
        tx_data = self._tx_to_bytes(tx)
        self._db.put((self._cf_tx, key), tx_data)
        meta_data = tx.get_metadata(use_storage=False).to_bytes()
        self._db.put((self._cf_meta, key), meta_data)

    @override
    def _save_static_metadata(self, tx: 'BaseTransaction') -> None:
        self._db.put((self._cf_static_meta, tx.hash), tx.static_metadata.json_dumpb())

    def _load_static_metadata(self, vertex: 'BaseTransaction') -> None:
        """Set vertex static metadata loaded from what's saved in this storage."""
        if vertex.is_genesis:
            vertex.init_static_metadata_from_storage(self._settings, self)
            return
        data = self._db.get((self._cf_static_meta, vertex.hash))
        assert data is not None, f'static metadata not found for vertex {vertex.hash_hex}'
        static_metadata = VertexStaticMetadata.from_bytes(data, target=vertex)
        vertex.set_static_metadata(static_metadata)

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        if hash_bytes in self.cache_data.cache:
            return True
        may_exist, _ = self._db.key_may_exist((self._cf_tx, hash_bytes))
        if not may_exist:
            return False
        tx_exists = self._db.get((self._cf_tx, hash_bytes)) is not None
        return tx_exists

    def _get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        if tx := self.cache_data.cache.get(hash_bytes):
            self.cache_data.cache.move_to_end(hash_bytes, last=True)
            self.cache_data.hit += 1
            self._save_to_weakref(tx)
            return tx

        if tx := self.get_transaction_from_weakref(hash_bytes):
            self.cache_data.hit += 1
            self._update_cache(tx)
            return tx

        tx = self._get_transaction_from_db(hash_bytes)
        if not tx:
            raise TransactionDoesNotExist(hash_bytes.hex())

        assert tx._metadata is not None
        assert tx._static_metadata is not None
        assert tx.hash == hash_bytes

        self.cache_data.miss += 1
        self._update_cache(tx)
        self._save_to_weakref(tx)
        return tx

    def _get_transaction_from_db(self, hash_bytes: bytes) -> Optional['BaseTransaction']:
        key = hash_bytes
        tx_data = self._db.get((self._cf_tx, key))
        meta_data = self._db.get((self._cf_meta, key))
        if tx_data is None:
            return None
        assert meta_data is not None, 'expected metadata to exist when tx exists'
        tx = self._load_from_bytes(tx_data, meta_data)
        self._load_static_metadata(tx)
        return tx

    def _get_tx(self, hash_bytes: bytes, tx_data: bytes) -> 'BaseTransaction':
        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is None:
            meta_data = self._db.get((self._cf_meta, hash_bytes))
            tx = self._load_from_bytes(tx_data, meta_data)
            self._load_static_metadata(tx)
            assert tx.hash == hash_bytes
            self._save_to_weakref(tx)
        return tx

    def _get_all_transactions(self) -> Iterator['BaseTransaction']:
        self._flush_to_storage(self.cache_data.dirty_txs.copy())
        items = self._db.iteritems(self._cf_tx)
        items.seek_to_first()

        for key, tx_data in items:
            _, hash_bytes = key

            lock = self._get_lock(hash_bytes)
            if lock:
                with lock:
                    tx = self._get_tx(hash_bytes, tx_data)
            else:
                tx = self._get_tx(hash_bytes, tx_data)

            assert tx is not None
            yield tx

    def is_empty(self) -> bool:
        self._flush_to_storage(self.cache_data.dirty_txs.copy())
        # We consider 3 or less transactions as empty, because we want to ignore the genesis
        # block and txs
        keys = self._db.iterkeys(self._cf_tx)
        keys.seek_to_first()
        count = 0

        for key in keys:
            count += 1
            if count > 3:
                return False

        return True

    def get_sst_files_sizes_by_cf(
        self,
        cfs: Optional[list['rocksdb.ColumnFamilyHandle']] = None
    ) -> dict[bytes, float]:
        """Get the SST files sizes of each Column Family in bytes

        :param cfs: The list of column families, defaults to None, in which case all of them are returned
        :return: A dict containing the names of the cfs and their sizes
        """
        column_families = self._db.column_families if cfs is None else cfs

        sizes: dict[bytes, float] = {}

        for cf in column_families:
            sizes[cf.name] = float(self._db.get_property(b'rocksdb.total-sst-files-size', cf))

        return sizes

    def add_value(self, key: str, value: str) -> None:
        self._db.put((self._cf_attr, key.encode('utf-8')), value.encode('utf-8'))

    def remove_value(self, key: str) -> None:
        self._db.delete((self._cf_attr, key.encode('utf-8')))

    def get_value(self, key: str) -> Optional[str]:
        data = self._db.get((self._cf_attr, key.encode('utf-8')))

        if data is None:
            return None
        else:
            return data.decode()

    @override
    def migrate_vertex_children(self) -> None:
        """Migrate vertex children from metadata to their own column family."""
        import rocksdb
        assert isinstance(self.vertex_children, RocksDBVertexChildrenService)

        def get_old_children_set(vertex_id: VertexId) -> set[VertexId]:
            meta_bytes = self._db.get((self._cf_meta, vertex_id))
            assert isinstance(meta_bytes, bytes)
            meta_dict = json_loadb(meta_bytes)
            children = meta_dict['children']
            assert isinstance(children, list)
            children_set = set(children)
            assert len(children) == len(children_set)  # sanity check whether we have duplicate children
            return {bytes.fromhex(child_id) for child_id in children_set}

        batch = rocksdb.WriteBatch()
        max_writes_per_batch = 10_000

        self.log.info('copying vertex children to new structure...')
        for vertex in progress(self._get_all_transactions(), log=self.log, total=None):
            for child_id in get_old_children_set(vertex.hash):
                # Manually write children to the cf instead of using the VertexChildrenService so we can use WriteBatch
                key = RocksDBVertexChildrenService._to_key(vertex, child_id)
                batch.put((self.vertex_children._cf, key), b'')

                if batch.count() >= max_writes_per_batch:
                    self._db.write(batch)
                    batch.clear()

        self._db.write(batch)  # one last write to clear the last batch

        self.log.info('removing old vertex children metadata...')
        for vertex in progress(self._get_all_transactions(), log=self.log, total=None):
            # sanity check to confirm the migration was correct.
            assert get_old_children_set(vertex.hash) == set(self.vertex_children.get_children(vertex))
            # saving metadata will remove the children list from the stored json.
            self.save_transaction(vertex, only_metadata=True)
