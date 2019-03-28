import rocksdb

from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.util import deprecated, skip_warning


class TransactionRocksDBStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    """This storage saves tx and metadata to the same key on RocksDB

    It uses Protobuf serialization internally.
    """

    def __init__(self, path='./storage.db', with_index=True):
        super().__init__(with_index=with_index)
        self._db = rocksdb.DB(path, rocksdb.Options(create_if_missing=True))

    def _load_from_bytes(self, data: bytes):
        from hathor.protos import BaseTransaction
        from hathor.transaction.base_transaction import tx_or_block_from_proto

        tx_proto = BaseTransaction()
        tx_proto.ParseFromString(data)
        return tx_or_block_from_proto(tx_proto, storage=self)

    def _tx_to_bytes(self, tx) -> bytes:
        tx_proto = tx.to_proto()
        return tx_proto.SerializeToString()

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        if tx.is_genesis:
            return
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx, *, only_metadata=False):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis:
            return
        data = self._tx_to_bytes(tx)
        key = tx.hash
        self._db.put(key, data)

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return True
        may_exist, _ = self._db.key_may_exist(hash_bytes)
        if not may_exist:
            return False
        tx_exists = self._get_transaction(hash_bytes) is not None
        return tx_exists

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return genesis

        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        tx = self._get_transaction(hash_bytes)
        if not tx:
            raise TransactionDoesNotExist(hash_bytes.hex())

        assert tx.hash == hash_bytes

        self._save_to_weakref(tx)
        return tx

    def _get_transaction(self, hash_bytes):
        key = hash_bytes
        data = self._db.get(key)
        if data is None:
            return
        tx = self._load_from_bytes(data)
        return tx

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        for tx in self.get_all_genesis():
            yield tx

        items = self._db.iteritems()
        items.seek_to_first()
        for key, data in items:
            hash_bytes = key

            tx = self.get_transaction_from_weakref(hash_bytes)
            if tx is not None:
                yield tx
                continue

            tx = self._load_from_bytes(data)
            assert tx.hash == hash_bytes
            self._save_to_weakref(tx)
            yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        # XXX: there may be a more efficient way, see: https://stackoverflow.com/a/25775882
        keys = self._db.iterkeys()
        keys.seek_to_first()
        keys_count = sum(1 for _ in keys)
        return genesis_len + keys_count
