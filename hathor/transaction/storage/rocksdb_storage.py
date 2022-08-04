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

from hathor.indexes import IndexesManager, MemoryIndexesManager, RocksDBIndexesManager
from hathor.storage import RocksDBStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, TransactionMetadata

logger = get_logger()

_DB_NAME = 'data_v2.db'
_CF_NAME_TX = b'tx'
_CF_NAME_META = b'meta'
_CF_NAME_ATTR = b'attr'


class TransactionRocksDBStorage(BaseTransactionStorage):
    """This storage saves tx and metadata to the same key on RocksDB

    It uses Protobuf serialization internally.
    """

    def __init__(self, rocksdb_storage: RocksDBStorage, with_index: bool = True, use_memory_indexes: bool = False):
        self._use_memory_indexes = use_memory_indexes

        self._cf_tx = rocksdb_storage.get_or_create_column_family(_CF_NAME_TX)
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_META)
        self._cf_attr = rocksdb_storage.get_or_create_column_family(_CF_NAME_ATTR)

        self._db = rocksdb_storage.get_db()
        super().__init__(with_index=with_index)

    def _load_from_bytes(self, tx_data: bytes, meta_data: bytes) -> 'BaseTransaction':
        from hathor.transaction.base_transaction import tx_or_block_from_bytes
        from hathor.transaction.transaction_metadata import TransactionMetadata

        tx = tx_or_block_from_bytes(tx_data)
        tx._metadata = TransactionMetadata.create_from_json(json_loadb(meta_data))
        tx.storage = self
        return tx

    def _build_indexes_manager(self) -> IndexesManager:
        if self._use_memory_indexes:
            return MemoryIndexesManager()
        else:
            return RocksDBIndexesManager(self._db)

    def _tx_to_bytes(self, tx: 'BaseTransaction') -> bytes:
        return bytes(tx)

    def _meta_to_bytes(self, meta: 'TransactionMetadata') -> bytes:
        return json_dumpb(meta.to_json())

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

    def get_all_transactions(self) -> Iterator['BaseTransaction']:
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

    def get_count_tx_blocks(self) -> int:
        keys_bcount = self._db.get_property(b'rocksdb.estimate-num-keys', self._cf_tx)
        keys_count = int(keys_bcount)
        return keys_count

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
