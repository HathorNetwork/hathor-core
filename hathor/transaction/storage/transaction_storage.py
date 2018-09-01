from hathor.transaction.storage import genesis_transactions


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

    def get_metadata_by_hash(self, hash_hex):
        raise NotImplementedError

    def get_metadata_by_hash_bytes(self, hash_bytes):
        raise NotImplementedError

    def get_genesis_by_hash_bytes(self, hash_bytes):
        """
            Returning hardcoded genesis block and transactions
        """
        for genesis in genesis_transactions():
            if hash_bytes == genesis.hash:
                return genesis

        return None

    def get_all_transactions(self):
        raise NotImplementedError

    def get_latest_transactions(self, count=2):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        transactions = list(self.get_all_transactions())

        genesis = genesis_transactions()
        for g in genesis:
            if not g.is_block:
                transactions.append(g)

        transactions = sorted(transactions, key=lambda t: t.timestamp, reverse=True)
        return transactions[:count]
