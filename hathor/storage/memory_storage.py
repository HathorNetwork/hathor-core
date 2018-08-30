from hathor.storage.transaction_storage import TransactionStorage
from hathor.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist


class TransactionMemoryStorage(TransactionStorage):
    def __init__(self):
        self.transactions = {}
        self.metadata = {}

    def save_transaction(self, tx):
        hash_hex = tx.hash.hex()
        self.transactions[hash_hex] = tx

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

    def get_metadata(self, hash_hex):
        if hash_hex in self.metadata:
            return self.metadata[hash_hex]
        else:
            raise TransactionMetadataDoesNotExist

    def save_metadata(self, metadata):
        hash_hex = metadata.hash.hex()
        self.metadata[hash_hex] = metadata
