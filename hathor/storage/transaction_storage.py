class TransactionStorage:
    def save_transaction(self, tx):
        raise NotImplementedError

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_transaction_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_transaction_by_hash(self, hash_hex):
        raise NotImplementedError

    def update_metadata(self, hash_hex, data):
        raise NotImplementedError

    def get_metadata(self, hash_hex):
        raise NotImplementedError

    def get_genesis_by_hash_bytes(self, hash_bytes):
        """
            Returning hardcoded genesis block and transactions
        """
        for genesis in get_genesis_transactions():
            if hash_bytes == genesis.hash:
                return genesis

        return None


# So we can reuse the instance (like a singleton)
# and have more than one (for testnet and mainnet, for example) - that's why we don't use a singleton
default_instance = [None]


def get_default_transaction_storage():
    # TODO Get from config file the default storage
    from hathor.storage.json_storage import TransactionJSONStorage
    if default_instance[0] is None:
        default_instance[0] = TransactionJSONStorage()
    return default_instance[0]


def get_genesis_transactions():
    from hathor.transaction.transaction import TX_GENESIS1, TX_GENESIS2
    from hathor.transaction.block import BLOCK_GENESIS
    return [
        BLOCK_GENESIS,
        TX_GENESIS1,
        TX_GENESIS2
    ]
