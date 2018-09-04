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
        hash_hex = tx.hash.hex()
        self.transactions[hash_hex] = tx
        if tx.is_block:
            self._blocks_by_height[tx.height].append(tx)

    def transaction_exists_by_hash(self, hash_hex):
        return hash_hex in self.transactions

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        return self.transaction_exists_by_hash(hash_hex)

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis

        hash_hex = hash_bytes.hex()
        if hash_hex in self.transactions:
            return self.transactions[hash_hex]
        else:
            raise TransactionDoesNotExist

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def get_metadata_by_hash_bytes(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        return self.get_metadata_by_hash(hash_hex)

    def get_metadata_by_hash(self, hash_hex):
        if hash_hex in self.metadata:
            return self.metadata[hash_hex]
        else:
            raise TransactionMetadataDoesNotExist

    def save_metadata(self, metadata):
        hash_hex = metadata.hash.hex()
        self.metadata[hash_hex] = metadata

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
