from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import deprecated, skip_warning


class TransactionMemoryStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, with_index=True):
        self.transactions = {}
        self.metadata = {}
        super().__init__(with_index=with_index)

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        if not only_metadata:
            self.transactions[tx.hash] = tx
        self._save_metadata(tx)

    def _save_metadata(self, tx):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis:
            return
        meta = getattr(tx, '_metadata', None)
        if meta:
            self.metadata[tx.hash] = meta

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return True
        return hash_bytes in self.transactions

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return genesis

        if hash_bytes in self.transactions:
            tx = self.transactions[hash_bytes]
            if hash_bytes in self.metadata:
                tx._metadata = self.metadata[hash_bytes]
            return tx
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        for tx in self.get_all_genesis():
            if tx.hash in self.metadata:
                tx._metadata = self.metadata[tx.hash]
            yield tx
        for tx in self.transactions.values():
            if tx.hash in self.metadata:
                tx._metadata = self.metadata[tx.hash]
            yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        return len(self.transactions) + genesis_len
