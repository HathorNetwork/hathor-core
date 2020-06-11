import os
from typing import TYPE_CHECKING, Iterator, Optional

from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


class TransactionRocksDBStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    """This storage saves tx and metadata to the same key on RocksDB

    It uses Protobuf serialization internally.
    """

    def __init__(self, path='./', with_index=True):
        import rocksdb
        tx_dir = os.path.join(path, 'tx.db')
        self._db = rocksdb.DB(tx_dir, rocksdb.Options(create_if_missing=True))

        attributes_dir = os.path.join(path, 'attributes.db')
        self.attributes_db = rocksdb.DB(attributes_dir, rocksdb.Options(create_if_missing=True))
        super().__init__(with_index=with_index)

    def _load_from_bytes(self, data: bytes) -> 'BaseTransaction':
        from hathor import protos
        from hathor.transaction.base_transaction import tx_or_block_from_proto

        tx_proto = protos.BaseTransaction()
        tx_proto.ParseFromString(data)
        return tx_or_block_from_proto(tx_proto, storage=self)

    def _tx_to_bytes(self, tx: 'BaseTransaction') -> bytes:
        tx_proto = tx.to_proto()
        return tx_proto.SerializeToString()

    def remove_transaction(self, tx: 'BaseTransaction') -> None:
        super().remove_transaction(tx)
        self._db.delete(tx.hash)
        self._remove_from_weakref(tx)

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        data = self._tx_to_bytes(tx)
        key = tx.hash
        self._db.put(key, data)

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        may_exist, _ = self._db.key_may_exist(hash_bytes)
        if not may_exist:
            return False
        tx_exists = self._get_transaction_from_db(hash_bytes) is not None
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
        data = self._db.get(key)
        if data is None:
            return None
        tx = self._load_from_bytes(data)
        return tx

    def get_all_transactions(self) -> Iterator['BaseTransaction']:
        tx: Optional['BaseTransaction']

        items = self._db.iteritems()
        items.seek_to_first()

        def get_tx(hash_bytes, data):
            tx = self.get_transaction_from_weakref(hash_bytes)
            if tx is None:
                tx = self._load_from_bytes(data)
                assert tx.hash == hash_bytes
                self._save_to_weakref(tx)
            return tx

        for key, data in items:
            hash_bytes = key

            lock = self._get_lock(hash_bytes)
            if lock:
                with lock:
                    tx = get_tx(hash_bytes, data)
            else:
                tx = get_tx(hash_bytes, data)

            assert tx is not None
            yield tx

    def get_count_tx_blocks(self) -> int:
        # XXX: there may be a more efficient way, see: https://stackoverflow.com/a/25775882
        keys = self._db.iterkeys()
        keys.seek_to_first()
        keys_count = sum(1 for _ in keys)
        return keys_count

    def add_value(self, key: str, value: str) -> None:
        self.attributes_db.put(key.encode('utf-8'), value.encode('utf-8'))

    def remove_value(self, key: str) -> None:
        self.attributes_db.delete(key.encode('utf-8'))

    def get_value(self, key: str) -> Optional[str]:
        data = self.attributes_db.get(key.encode('utf-8'))
        if data is None:
            return None
        else:
            return data.decode()
