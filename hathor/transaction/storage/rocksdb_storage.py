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

from typing import TYPE_CHECKING, Iterator, Optional

from structlog import get_logger
from typing_extensions import override

from hathor.indexes import IndexesManager
from hathor.storage import RocksDBStorage
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.migrations import MigrationState
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
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
        rocksdb_storage: RocksDBStorage,
        indexes: Optional[IndexesManager] = None,
        *,
        settings: 'HathorSettings',
        vertex_parser: VertexParser,
        nc_storage_factory: NCStorageFactory,
        vertex_children_service: RocksDBVertexChildrenService,
    ) -> None:
        self._cf_tx = rocksdb_storage.get_or_create_column_family(_CF_NAME_TX)
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)
        self._cf_static_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_STATIC_META)
        self._cf_attr = rocksdb_storage.get_or_create_column_family(_CF_NAME_ATTR)
        self._cf_migrations = rocksdb_storage.get_or_create_column_family(_CF_NAME_MIGRATIONS)

        self._rocksdb_storage = rocksdb_storage
        self._db = rocksdb_storage.get_db()
        self.vertex_parser = vertex_parser
        super().__init__(
            indexes=indexes,
            settings=settings,
            nc_storage_factory=nc_storage_factory,
            vertex_children_service=vertex_children_service,
        )

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
        self._db.delete((self._cf_tx, tx.hash))
        self._db.delete((self._cf_meta, tx.hash))
        self._db.delete((self._cf_static_meta, tx.hash))
        self._remove_from_weakref(tx)

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        key = tx.hash
        if not only_metadata:
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
        may_exist, _ = self._db.key_may_exist((self._cf_tx, hash_bytes))
        if not may_exist:
            return False
        tx_exists = self._db.get((self._cf_tx, hash_bytes)) is not None
        return tx_exists

    def _get_transaction(self, hash_bytes: bytes) -> 'BaseTransaction':
        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        tx = self._get_transaction_from_db(hash_bytes)
        if not tx:
            raise TransactionDoesNotExist(hash_bytes.hex())

        assert tx._metadata is not None
        assert tx._static_metadata is not None
        assert tx.hash == hash_bytes

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
        tx: Optional['BaseTransaction']

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
