# So we can reuse the instance (like a singleton)
# and have more than one (for testnet and mainnet, for example) - that's why we don't use a singleton
default_instance = [None]


def default_transaction_storage():
    # TODO Get from config file the default storage
    from hathor.transaction.storage.json_storage import TransactionJSONStorage
    if default_instance[0] is None:
        default_instance[0] = TransactionJSONStorage()
    return default_instance[0]


def genesis_transactions():
    from hathor.transaction.transaction import TX_GENESIS1, TX_GENESIS2
    from hathor.transaction.block import BLOCK_GENESIS
    return [
        BLOCK_GENESIS,
        TX_GENESIS1,
        TX_GENESIS2
    ]
