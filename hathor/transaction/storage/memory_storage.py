from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist

from collections import defaultdict


class TransactionMemoryStorage(TransactionStorage):
    def __init__(self):
        self.transactions = {}
        self.metadata = {}
        self._blocks_by_height = defaultdict(list)  # map from height to a list of blocks at that height.
        super().__init__()

    def save_transaction(self, tx):
        super().save_transaction(tx)
        self.transactions[tx.hash] = tx
        if tx.is_block:
            self._blocks_by_height[tx.height].append(tx)

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
            return self.transactions[hash_bytes]
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def get_metadata_by_hash_bytes(self, hash_bytes):
        if hash_bytes in self.metadata:
            return self.metadata[hash_bytes]
        else:
            raise TransactionMetadataDoesNotExist(hash_bytes.hex())

    def get_metadata_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_metadata_by_hash_bytes(self, hash_bytes)

    def save_metadata(self, metadata):
        self.metadata[metadata.hash] = metadata

    def get_all_transactions(self):
        """Return all transactions that are not blocks"""
        from hathor.transaction.genesis import genesis_transactions
        for tx in genesis_transactions(self):
            yield tx
        for tx in self.transactions.values():
            yield tx

    def get_blocks_at_height(self, height):
        return self._blocks_by_height[height]

    def get_block_hashes_at_height(self, height):
        return [x.hash for x in self._blocks_by_height[height]]

    def get_count_tx_blocks(self):
        from hathor.transaction.genesis import genesis_transactions
        genesis_len = len([tx for tx in genesis_transactions(self)])
        return len(self.transactions) + genesis_len
