# encoding: utf-8
from hathor.transaction.storage.exceptions import TransactionIsNotABlock


class TransactionStorage:
    def __init__(self):
        self._init_caches()
        if self.__class__ == TransactionStorage:
            raise Exception('You cannot directly create an instance of this class.')

    def _init_caches(self):
        self._cache_tip_blocks = set()
        self._cache_block_counts = 0
        for tx in self.get_all_transactions():
            if tx.is_block:
                self._add_block_to_cache(tx)

    def _add_block_to_cache(self, tx):
        if not tx.is_block:
            return
        for parent in tx.parents:
            if parent.hex() in self._cache_tip_blocks:
                self._cache_tip_blocks.remove(parent.hex())
        self._cache_tip_blocks.add(tx.hash.hex())
        self._cache_block_counts += 1

    def count_blocks(self):
        return self._cache_block_counts

    def save_transaction(self, tx):
        if tx.is_block:
            self._add_block_to_cache(tx)

    def transaction_exists_by_hash(self, hash_hex):
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
        from hathor.transaction.genesis import genesis_transactions
        for genesis in genesis_transactions(self):
            if hash_bytes == genesis.hash:
                return genesis

        return None

    def get_all_transactions(self):
        raise NotImplementedError

    def get_tip_blocks(self):
        ret = []
        for hash_hex in self._cache_tip_blocks:
            ret.append(bytes.fromhex(hash_hex))
        return ret

    def get_latest_block(self):
        blocks = self.get_latest_blocks(5)

        assert blocks, 'No tip blocks available, not even genesis!'

        sorted_blocks = sorted(blocks, key=lambda b: b.height, reverse=True)
        return sorted_blocks[0]

    def get_best_height(self):
        """Returns the height for the most recent block."""
        latest_block = self.get_latest_block()
        return latest_block.height

    def get_latest_blocks(self, count=2):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        blocks = list(tx for tx in self.get_all_transactions() if tx.is_block)
        blocks = sorted(blocks, key=lambda t: t.timestamp, reverse=True)
        return blocks[:count]

    def get_blocks_at_height(self, height):
        """Returns a list of all stored block objects with the given height."""
        raise NotImplementedError

    def get_block_hashes_at_height(self, height):
        """Returns a list of all stored block objects with the given height."""
        raise NotImplementedError

    def get_block_hashes_after(self, hash_hex, num_blocks=100):
        """Retrieve the next num_blocks block hashes after the given hash. Return value is a list of hashes."""
        hashes = []
        tx = self.get_transaction_by_hash(hash_hex)
        if not tx.is_block:
            raise TransactionIsNotABlock
        for i in range(tx.height + 1, tx.height + 1 + num_blocks):
            for h in self.get_block_hashes_at_height(i):
                hashes.append(h)
        return hashes

    def get_tip_transactions(self, count=2):
        tips = self.get_latest_transactions(count)
        ret = []
        for tx in tips:
            ret.append(tx.hash)
        return ret

    def get_all_genesis(self):
        from hathor.transaction.genesis import genesis_transactions
        return genesis_transactions(self)

    def get_latest_transactions(self, count=2):
        # XXX Just for testing, transforming generator into list would be impossible with many transactions
        transactions = list(tx for tx in self.get_all_transactions() if not tx.is_block)
        transactions = sorted(transactions, key=lambda t: t.timestamp, reverse=True)
        return transactions[:count]
