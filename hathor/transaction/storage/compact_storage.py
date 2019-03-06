import base64
import glob
import json
import os
import re

from hathor.constants import STORAGE_SUBFOLDERS
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning


class TransactionCompactStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    """This storage saves tx and metadata in the same file.

    It also uses JSON format. Saved file is of format {'tx': {...}, 'meta': {...}}
    """

    def __init__(self, path='./', with_index=True):
        os.makedirs(path, exist_ok=True)
        self.path = path
        super().__init__(with_index=with_index)

        filename_pattern = r'^tx_([\dabcdef]{64})\.json$'
        self.re_pattern = re.compile(filename_pattern)
        self.create_subfolders(self.path, STORAGE_SUBFOLDERS)

    def create_subfolders(self, path: str, num_subfolders: int):
        """ Create subfolders in the main tx storage folder.

        :param path: the main tx storage folder
        :type path: str

        :param num_subfolders: number of subfolders to create
        :type num_subfolders: int
        """
        # create subfolders
        for i in range(num_subfolders):
            folder = '%0.2x' % i
            os.makedirs(os.path.join(path, folder), exist_ok=True)

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)

    def _save_transaction(self, tx, *, only_metadata=False):
        # genesis txs and metadata are kept in memory
        if tx.is_genesis:
            return
        data = {}
        data['tx'] = tx.to_json()
        meta = getattr(tx, '_metadata', None)
        if meta:
            data['meta'] = tx._metadata.to_json()
        filepath = self.generate_filepath(tx.hash)
        self.save_to_json(filepath, data)
        self._save_to_weakref(tx)

    def generate_filepath(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        filename = 'tx_{}.json'.format(hash_hex)
        subfolder = hash_hex[-2:]
        filepath = os.path.join(self.path, subfolder, filename)
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
            json_file.write(json.dumps(data))

    def load_from_json(self, filepath, error):
        if os.path.isfile(filepath):
            with open(filepath, 'r') as json_file:
                dict_data = json.loads(json_file.read())
                return dict_data
        else:
            raise error

    def load(self, data):
        from hathor.transaction.transaction import Transaction
        from hathor.transaction.block import Block
        from hathor.transaction.base_transaction import TxOutput, TxInput

        nonce = data['nonce']
        timestamp = data['timestamp']
        version = data['version']
        weight = data['weight']
        hash_bytes = bytes.fromhex(data['hash'])

        parents = []
        for parent in data['parents']:
            parents.append(bytes.fromhex(parent))

        inputs = []
        for input_tx in data['inputs']:
            tx_id = bytes.fromhex(input_tx['tx_id'])
            index = input_tx['index']
            input_data = base64.b64decode(input_tx['data'])
            inputs.append(TxInput(tx_id, index, input_data))

        outputs = []
        for output in data['outputs']:
            value = output['value']
            script = base64.b64decode(output['script'])
            outputs.append(TxOutput(value, script))

        tokens = [bytes.fromhex(uid) for uid in data['tokens']]

        kwargs = {
            'nonce': nonce,
            'timestamp': timestamp,
            'version': version,
            'weight': weight,
            'outputs': outputs,
            'parents': parents,
            'storage': self,
        }

        if len(inputs) == 0:
            kwargs['data'] = base64.b64decode(data['data'])
            tx = Block(**kwargs)
        else:
            kwargs['inputs'] = inputs
            kwargs['tokens'] = tokens
            tx = Transaction(**kwargs)
        tx.update_hash()
        assert tx.hash == hash_bytes, 'Hashes differ: {} != {}'.format(tx.hash.hex(), hash_bytes.hex())
        return tx

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return genesis

        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        filepath = self.generate_filepath(hash_bytes)
        data = self.load_from_json(filepath, TransactionDoesNotExist(hash_bytes.hex()))
        tx = self.load(data['tx'])
        if 'meta' in data.keys():
            meta = TransactionMetadata.create_from_json(data['meta'])
            tx._metadata = meta
        self._save_to_weakref(tx)
        return tx

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        for tx in self.get_all_genesis():
            yield tx

        for f in glob.iglob(os.path.join(self.path, '*/*')):
            match = self.re_pattern.match(os.path.basename(f))
            if match:
                hash_bytes = bytes.fromhex(match.groups()[0])
                tx = self.get_transaction_from_weakref(hash_bytes)
                if tx is not None:
                    yield tx
                else:
                    # TODO Return a proxy that will load the transaction only when it is used.
                    data = self.load_from_json(f, TransactionDoesNotExist())
                    tx = self.load(data['tx'])
                    if 'meta' in data.keys():
                        meta = TransactionMetadata.create_from_json(data['meta'])
                        tx._metadata = meta
                    self._save_to_weakref(tx)
                    yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        files = [f for f in glob.iglob(os.path.join(self.path, '*/*')) if self.re_pattern.match(f)]
        return len(files) + genesis_len
