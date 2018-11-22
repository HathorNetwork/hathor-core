from hathor.transaction.storage.transaction_storage import TransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning

import json
import os
import re


class TransactionBinaryStorage(TransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, path='./',  with_index=True):
        os.makedirs(path, exist_ok=True)
        self.path = path
        super().__init__(with_index=with_index)

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        if not only_metadata:
            self._save_transaction(tx)
        self._save_metadata(tx)

    def _save_transaction(self, tx):
        tx_bytes = tx.get_struct()
        filepath = self.generate_filepath(tx.hash)
        with open(filepath, 'wb') as fp:
            fp.write(tx_bytes)
        if tx.is_block:
            self._save_blockhash_by_height(tx)

    def _save_metadata(self, tx):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis:
            return
        metadata = tx.get_metadata()
        data = self.serialize_metadata(metadata)
        filepath = self.generate_metadata_filepath(tx.hash)
        self.save_to_json(filepath, data)

    def generate_filepath(self, hash_bytes):
        filename = 'tx_{}.bin'.format(hash_bytes.hex())
        filepath = os.path.join(self.path, filename)
        return filepath

    def serialize_metadata(self, metadata):
        return metadata.to_json()

    def load_metadata(self, data):
        return TransactionMetadata.create_from_json(data)

    def generate_metadata_filepath(self, hash_bytes):
        filename = 'tx_{}_metadata.json'.format(hash_bytes.hex())
        filepath = os.path.join(self.path, filename)
        return filepath

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return True
        filepath = self.generate_filepath(hash_bytes)
        return os.path.isfile(filepath)

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

    def load_transaction(self, hash_bytes):
        filepath = self.generate_filepath(hash_bytes)
        return self._load_transaction_from_filepath(filepath)

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return genesis

        tx = self.load_transaction(hash_bytes)
        try:
            meta = self._get_metadata_by_hash(hash_bytes)
            tx._metadata = meta
        except TransactionMetadataDoesNotExist:
            pass
        return tx

    def _get_metadata_by_hash(self, hash_bytes):
        filepath = self.generate_metadata_filepath(hash_bytes)
        data = self.load_from_json(filepath, TransactionMetadataDoesNotExist)
        return self.load_metadata(data)

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        for tx in self.get_all_genesis():
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

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        path = self.path
        files = os.listdir(path)
        return len(files) + genesis_len
