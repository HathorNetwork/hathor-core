import json
import os
import re
from typing import TYPE_CHECKING

from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


class TransactionBinaryStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, path='./', with_index=True):
        os.makedirs(path, exist_ok=True)
        self.path = path

        filename_pattern = r'^tx_([\dabcdef]{64})\.bin$'
        self.re_pattern = re.compile(filename_pattern)

        super().__init__(with_index=with_index)

    @deprecated('Use remove_transaction_deferred instead')
    def remove_transaction(self, tx):
        skip_warning(super().remove_transaction)(tx)
        filepath = self.generate_filepath(tx.hash)
        metadata_filepath = self.generate_metadata_filepath(tx.hash)
        self._remove_from_weakref(tx)

        try:
            os.unlink(filepath)
        except FileNotFoundError:
            pass

        try:
            os.unlink(metadata_filepath)
        except FileNotFoundError:
            pass

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx, *, only_metadata=False):
        if not only_metadata:
            self._save_tx_to_disk(tx)
        self._save_metadata(tx)

    def _save_tx_to_disk(self, tx):
        tx_bytes = tx.get_struct()
        filepath = self.generate_filepath(tx.hash)
        with open(filepath, 'wb') as fp:
            fp.write(tx_bytes)

    def _save_metadata(self, tx):
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

    def _load_transaction_from_filepath(self, filepath):
        try:
            with open(filepath, 'rb') as fp:
                tx_bytes = fp.read()
                tx = tx_or_block_from_bytes(tx_bytes)
                tx.storage = self
                tx.update_hash()
                return tx
        except FileNotFoundError:
            raise TransactionDoesNotExist

    def load_transaction(self, hash_bytes):
        filepath = self.generate_filepath(hash_bytes)
        return self._load_transaction_from_filepath(filepath)

    @deprecated('Use get_transaction_deferred instead')
    def _get_transaction(self, hash_bytes: bytes) -> 'BaseTransaction':
        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        tx = self.load_transaction(hash_bytes)
        try:
            meta = self._get_metadata_by_hash(hash_bytes)
            tx._metadata = meta
        except TransactionMetadataDoesNotExist:
            pass

        self._save_to_weakref(tx)
        return tx

    def _get_metadata_by_hash(self, hash_bytes):
        filepath = self.generate_metadata_filepath(hash_bytes)
        data = self.load_from_json(filepath, TransactionMetadataDoesNotExist)
        return self.load_metadata(data)

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        path = self.path
        with os.scandir(path) as it:
            for f in it:
                match = self.re_pattern.match(f.name)
                if match:
                    hash_bytes = bytes.fromhex(match.groups()[0])
                    lock = self._get_lock(hash_bytes)
                    with lock:
                        tx = self.get_transaction_from_weakref(hash_bytes)
                        if tx is None:
                            # TODO Return a proxy that will load the transaction only when it is used.
                            tx = self._load_transaction_from_filepath(f.path)
                            self._save_to_weakref(tx)
                    yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        files = os.listdir(self.path)
        assert len(files) % 2 == 0
        return len(files) // 2
