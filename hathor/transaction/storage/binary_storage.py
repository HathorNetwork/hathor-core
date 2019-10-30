import json
import os
import re
import struct

from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning


class TransactionBinaryStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, path='./', with_index=True):
        os.makedirs(path, exist_ok=True)
        self.path = path
        super().__init__(with_index=with_index)

        self.length_format = '!I'
        filename_pattern = r'^tx_([\dabcdef]{64})\.bin$'
        self.re_pattern = re.compile(filename_pattern)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, repr(self.path))

    @deprecated('Use remove_transaction_deferred instead')
    def remove_transaction(self, tx):
        skip_warning(super().remove_transaction)(tx)
        filepath = self.generate_filepath(tx.hash)
        self._remove_from_weakref(tx)

        try:
            os.unlink(filepath)
        except FileNotFoundError:
            pass

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        if tx.is_genesis:
            return
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx, *, only_metadata=False):
        if tx.is_genesis:
            return
        tx_bytes = tx.get_struct()

        meta = tx.get_metadata()
        if meta:
            meta_dict = self.serialize_metadata(meta)
            meta_bytes = json.dumps(meta_dict, indent=4).encode('utf-8')
        else:
            meta_bytes = None

        filepath = self.generate_filepath(tx.hash)
        with open(filepath, 'wb') as fp:
            fp.write(struct.pack(self.length_format, len(tx_bytes)))
            fp.write(tx_bytes)
            if meta_bytes:
                fp.write(meta_bytes)

    def generate_filepath(self, hash_bytes):
        filename = 'tx_{}.bin'.format(hash_bytes.hex())
        filepath = os.path.join(self.path, filename)
        return filepath

    def serialize_metadata(self, metadata):
        return metadata.to_json()

    def load_metadata(self, data):
        return TransactionMetadata.create_from_json(data)

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return True
        filepath = self.generate_filepath(hash_bytes)
        return os.path.isfile(filepath)

    def _load_transaction_from_filepath(self, filepath):
        try:
            length_size = struct.calcsize(self.length_format)
            with open(filepath, 'rb') as fp:
                (tx_bytes_len,) = struct.unpack(self.length_format, fp.read(length_size))
                tx_bytes = fp.read(tx_bytes_len)
                tx = tx_or_block_from_bytes(tx_bytes)
                tx.storage = self
                tx.update_hash()

                # Load metadata.
                meta_bytes = fp.read()
                if meta_bytes:
                    meta_dict = json.loads(meta_bytes)
                    meta = self.load_metadata(meta_dict)
                    tx._metadata = meta
                return tx
        except FileNotFoundError:
            raise TransactionDoesNotExist

    def load_transaction(self, hash_bytes):
        filepath = self.generate_filepath(hash_bytes)
        tx = self._load_transaction_from_filepath(filepath)
        assert tx.hash == hash_bytes, 'Hashes differ: {} != {}'.format(tx.hash.hex(), hash_bytes.hex())
        return tx

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes: bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return genesis

        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        tx = self.load_transaction(hash_bytes)
        self._save_to_weakref(tx)
        return tx

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        for tx in self.get_all_genesis():
            yield tx

        path = self.path

        with os.scandir(path) as it:
            for f in it:
                match = self.re_pattern.match(f.name)
                if match:
                    hash_bytes = bytes.fromhex(match.groups()[0])
                    tx = self.get_transaction_from_weakref(hash_bytes)
                    if tx is not None:
                        yield tx
                    else:
                        # TODO Return a proxy that will load the transaction only when it is used.
                        tx = self._load_transaction_from_filepath(f.path)
                        self._save_to_weakref(tx)
                        yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        path = self.path
        files = os.listdir(path)
        return len(files) + genesis_len
