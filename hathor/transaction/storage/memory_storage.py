from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist


class TransactionMemoryStorage(TransactionStorage):
    def __init__(self, with_index=True):
        self.transactions = {}
        self.metadata = {}
        super().__init__(with_index=with_index)

    def save_transaction(self, tx):
        super().save_transaction(tx)
        self._save_transaction(tx)

    def _save_transaction(self, tx):
        self.transactions[tx.hash] = tx

    def transaction_exists_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.transaction_exists_by_hash_bytes(hash_bytes)

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return True
        return hash_bytes in self.transactions

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis

        if hash_bytes in self.transactions:
            tx = self.transactions[hash_bytes]
            if hash_bytes in self.metadata:
                tx._metadata = self.metadata[hash_bytes]
            return tx
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def save_metadata(self, tx):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis:
            return
        meta = getattr(tx, '_metadata', None)
        if meta:
            self.metadata[tx.hash] = meta

    def _get_metadata_by_hash(self, hash_hex):
        try:
            return self.metadata[bytes.fromhex(hash_hex)]
        except KeyError:
            raise TransactionMetadataDoesNotExist

    def get_all_transactions(self):
        """Return all transactions that are not blocks"""
        for tx in self.get_all_genesis():
            if tx.hash in self.metadata:
                tx._metadata = self.metadata[tx.hash]
            yield tx
        for tx in self.transactions.values():
            if tx.hash in self.metadata:
                tx._metadata = self.metadata[tx.hash]
            yield tx

    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        return len(self.transactions) + genesis_len
