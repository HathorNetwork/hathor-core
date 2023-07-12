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

from typing import TYPE_CHECKING, Iterator, Optional

from structlog import get_logger

from hathor.indexes import IndexesManager
from hathor.storage import RocksDBStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.migrations import MigrationState
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    import rocksdb

    from hathor.transaction import BaseTransaction, TransactionMetadata

logger = get_logger()

_DB_NAME = 'data_v2.db'
_CF_NAME_TX = b'tx'
_CF_NAME_META = b'meta'
_CF_NAME_ATTR = b'attr'
_CF_NAME_MIGRATIONS = b'migrations'


class TransactionRocksDBStorage(BaseTransactionStorage):
    """This storage saves tx and metadata to the same key on RocksDB

    It uses Protobuf serialization internally.
    """

    def __init__(self, rocksdb_storage: RocksDBStorage, indexes: Optional[IndexesManager] = None):
        self._cf_tx = rocksdb_storage.get_or_create_column_family(_CF_NAME_TX)
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)
        self._cf_attr = rocksdb_storage.get_or_create_column_family(_CF_NAME_ATTR)
        self._cf_migrations = rocksdb_storage.get_or_create_column_family(_CF_NAME_MIGRATIONS)

        self._rocksdb_storage = rocksdb_storage
        self._db = rocksdb_storage.get_db()
        super().__init__(indexes=indexes)

    def _load_from_bytes(self, tx_data: bytes, meta_data: bytes) -> 'BaseTransaction':
        from hathor.transaction.base_transaction import tx_or_block_from_bytes
        from hathor.transaction.transaction_metadata import TransactionMetadata

        tx = tx_or_block_from_bytes(tx_data)
        tx._metadata = TransactionMetadata.create_from_json(json_loadb(meta_data))
        tx.storage = self
        return tx

    def _tx_to_bytes(self, tx: 'BaseTransaction') -> bytes:
        return bytes(tx)

    def _meta_to_bytes(self, meta: 'TransactionMetadata') -> bytes:
        return json_dumpb(meta.to_json())

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
        meta_data = self._meta_to_bytes(tx.get_metadata(use_storage=False))
        self._db.put((self._cf_meta, key), meta_data)

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
        return tx

    def _get_tx(self, hash_bytes: bytes, tx_data: bytes) -> 'BaseTransaction':
        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is None:
            meta_data = self._db.get((self._cf_meta, hash_bytes))
            tx = self._load_from_bytes(tx_data, meta_data)
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
