import json
import os
import re
from typing import TYPE_CHECKING

from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction_metadata import TransactionMetadata

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


class TransactionBinaryStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, path='./', with_index=True):
        os.makedirs(path, exist_ok=True)
        self.path = path

        filename_pattern = r'^tx_([\dabcdef]{64})\.bin$'
        self.re_pattern = re.compile(filename_pattern)

        super().__init__(with_index=with_index)

    def remove_transaction(self, tx):
        super().remove_transaction(tx)
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

    def save_transaction(self, tx, *, only_metadata=False):
        super().save_transaction(tx, only_metadata=only_metadata)
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

    def get_all_transactions(self):
        path = self.path

        def get_tx(hash_bytes, path):
            tx = self.get_transaction_from_weakref(hash_bytes)
            if tx is None:
                # TODO Return a proxy that will load the transaction only when it is used.
                tx = self._load_transaction_from_filepath(path)
                self._save_to_weakref(tx)
            return tx

        with os.scandir(path) as it:
            for f in it:
                match = self.re_pattern.match(f.name)
                if match:
                    hash_bytes = bytes.fromhex(match.groups()[0])
                    lock = self._get_lock(hash_bytes)

                    if lock:
                        with lock:
                            tx = get_tx(hash_bytes, f.path)
                    else:
                        tx = get_tx(hash_bytes, f.path)
                    yield tx

    def get_count_tx_blocks(self):
        files = os.listdir(self.path)
        assert len(files) % 2 == 0
        return len(files) // 2
