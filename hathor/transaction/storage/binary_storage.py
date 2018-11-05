from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.transaction_metadata import TransactionMetadata

import json
import os
import re


class TransactionBinaryStorage(TransactionStorage):
    def __init__(self, path='./'):
        os.makedirs(path, exist_ok=True)
        self.path = path
        super().__init__()

    def generate_filepath(self, hash_hex):
        filename = 'tx_{}.bin'.format(hash_hex)
        filepath = os.path.join(self.path, filename)
        return filepath

    def generate_metadata_filepath(self, hash_hex):
        filename = 'tx_{}_metadata.json'.format(hash_hex)
        filepath = os.path.join(self.path, filename)
        return filepath

    def transaction_exists_by_hash(self, hash_hex):
        """Return `True` if `hash_hex` exists.

        :param hash_hex: Hash in hexa that will be checked.
        :type hash_hex: str(hex)

        :rtype: bool
        """
        hash_bytes = bytes.fromhex(hash_hex)
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return True
        filepath = self.generate_filepath(hash_hex)
        return os.path.isfile(filepath)

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        return self.transaction_exists_by_hash(hash_hex)

    def save_to_json(self, filepath, data):
        with open(filepath, 'w') as json_file:
            json_file.write(json.dumps(data, indent=4))

    def load_from_json(self, filepath, error):
        if os.path.isfile(filepath):
            with open(filepath, 'r') as json_file:
                dict_data = json.loads(json_file.read())
                return dict_data
        else:
            raise error

    def save_transaction(self, tx):
        super().save_transaction(tx)
        tx_bytes = tx.get_struct()
        filepath = self.generate_filepath(tx.hash_hex)
        with open(filepath, 'wb') as fp:
            fp.write(tx_bytes)
        if tx.is_block:
            self._save_blockhash_by_height(tx)

    def generate_blocks_at_height_filepath(self, height):
        filename = 'blks_h_{}.json'.format(height)
        filepath = os.path.join(self.path, filename)
        return filepath

    def _save_blockhash_by_height(self, block):
        """Adds the given block's hash string to the list of block hashes at the given height.

        Input is a block object, but only the hash is saved, in a file with name based on the height of the block.
        """
        # Load existing blocks at height, if any.
        height = block.height
        data, filepath = self._get_block_hashes_at_height(height)
        hash_hex = block.hash.hex()
        if hash_hex not in data:
            data.append(hash_hex)
            self.save_to_json(filepath, data)

    def _get_block_hashes_at_height(self, height):
        """Returns a tuple of list of hashes of blocks at the given height and the storage filename."""
        filepath = self.generate_blocks_at_height_filepath(height)
        try:
            data = self.load_from_json(filepath, FileNotFoundError)
        except FileNotFoundError:
            data = []
        return data, filepath

    def get_block_hashes_at_height(self, height):
        """Returns a tuple of list of hashes of blocks at the given height and the storage filename."""
        data, _ = self._get_block_hashes_at_height(height)
        return data

    def get_blocks_at_height(self, height):
        """Returns a list of blocks at the given height."""
        hashes, _ = self._get_block_hashes_at_height(height)
        data = []
        for hash_hex in hashes:
            data.append(self.get_transaction_by_hash(hash_hex))
        return data

    def _load_transaction_from_filepath(self, filepath):
        try:
            with open(filepath, 'rb') as fp:
                from hathor.transaction import Transaction
                tx_bytes = fp.read()
                tx = Transaction.create_from_struct(tx_bytes)
                if len(tx.inputs) == 0:
                    from hathor.transaction import Block
                    tx = Block.create_from_struct(tx_bytes)
                tx.storage = self
                tx.update_hash()
                return tx
        except FileNotFoundError:
            raise TransactionDoesNotExist

    def load_transaction(self, hash_hex):
        filepath = self.generate_filepath(hash_hex)
        return self._load_transaction_from_filepath(filepath)

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis
        hash_hex = hash_bytes.hex()
        return self.load_transaction(hash_hex)

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def save_metadata(self, metadata):
        data = self.serialize_metadata(metadata)
        filepath = self.generate_metadata_filepath(data['hash'])
        self.save_to_json(filepath, data)

    def get_metadata_by_hash(self, hash_hex):
        filepath = self.generate_metadata_filepath(hash_hex)
        data = self.load_from_json(filepath, TransactionMetadataDoesNotExist)
        return self.load_metadata(data)

    def get_metadata_by_hash_bytes(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        return self.get_metadata_by_hash(hash_hex)

    def serialize_metadata(self, metadata):
        return metadata.to_json()

    def load_metadata(self, data):
        return TransactionMetadata.create_from_json(data)

    def get_all_transactions(self):
        from hathor.transaction.genesis import genesis_transactions
        for tx in genesis_transactions(self):
            yield tx

        path = self.path
        pattern = r'tx_[\dabcdef]{64}\.bin'
        re_pattern = re.compile(pattern)

        with os.scandir(path) as it:
            for f in it:
                if re_pattern.match(f.name):
                    # TODO Return a proxy that will load the transaction only when it is used.
                    tx = self._load_transaction_from_filepath(f.path)
                    yield tx

    def get_count_tx_blocks(self):
        from hathor.transaction.genesis import genesis_transactions
        genesis_len = len([tx for tx in genesis_transactions(self)])
        path = self.path
        files = os.listdir(path)
        return len(files) + genesis_len
