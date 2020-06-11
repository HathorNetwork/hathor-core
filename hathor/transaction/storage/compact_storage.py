import base64
import glob
import json
import os
import re
from typing import TYPE_CHECKING, Any, Dict, Iterator, Optional

from hathor.conf import HathorSettings
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction_metadata import TransactionMetadata

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction

settings = HathorSettings()


class TransactionCompactStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    """This storage saves tx and metadata in the same file.

    It also uses JSON format. Saved file is of format {'tx': {...}, 'meta': {...}}
    """

    def __init__(self, path: str = './', with_index: bool = True):
        self.tx_path = os.path.join(path, 'tx')
        os.makedirs(self.tx_path, exist_ok=True)

        filename_pattern = r'^tx_([\dabcdef]{64})\.json$'
        self.re_pattern = re.compile(filename_pattern)
        self.create_subfolders(self.tx_path, settings.STORAGE_SUBFOLDERS)

        self.attributes_path = os.path.join(path, 'attributes')
        os.makedirs(self.attributes_path, exist_ok=True)

        super().__init__(with_index=with_index)

    def create_subfolders(self, path: str, num_subfolders: int) -> None:
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

    def remove_transaction(self, tx: 'BaseTransaction') -> None:
        assert tx.hash is not None
        super().remove_transaction(tx)
        filepath = self.generate_filepath(tx.hash)
        self._remove_from_weakref(tx)
        try:
            os.unlink(filepath)
        except FileNotFoundError:
            pass

    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)
        self._save_to_weakref(tx)

    def _save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        assert tx.hash is not None
        data = {}
        data['tx'] = tx.to_json()
        meta = getattr(tx, '_metadata', None)
        if meta:
            data['meta'] = meta.to_json()
        filepath = self.generate_filepath(tx.hash)
        self.save_to_json(filepath, data)

    def generate_filepath(self, hash_bytes: bytes) -> str:
        hash_hex = hash_bytes.hex()
        filename = 'tx_{}.json'.format(hash_hex)
        subfolder = hash_hex[-2:]
        filepath = os.path.join(self.tx_path, subfolder, filename)
        return filepath

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        filepath = self.generate_filepath(hash_bytes)
        return os.path.isfile(filepath)

    def save_to_json(self, filepath: str, data: Dict[str, Any]) -> None:
        with open(filepath, 'w') as json_file:
            json_file.write(json.dumps(data))

    def load_from_json(self, filepath: str, error: Exception) -> Dict[str, Any]:
        if os.path.isfile(filepath):
            with open(filepath, 'r') as json_file:
                dict_data = json.loads(json_file.read())
                return dict_data
        else:
            raise error

    def load(self, data: Dict[str, Any]) -> 'BaseTransaction':
        from hathor.transaction.aux_pow import BitcoinAuxPow
        from hathor.transaction.base_transaction import TxInput, TxOutput, TxVersion

        hash_bytes = bytes.fromhex(data['hash'])
        if 'data' in data:
            data['data'] = base64.b64decode(data['data'])

        parents = []
        for parent in data['parents']:
            parents.append(bytes.fromhex(parent))
        data['parents'] = parents

        inputs = []
        for input_tx in data['inputs']:
            tx_id = bytes.fromhex(input_tx['tx_id'])
            index = input_tx['index']
            input_data = base64.b64decode(input_tx['data'])
            inputs.append(TxInput(tx_id, index, input_data))
        if len(inputs) > 0:
            data['inputs'] = inputs
        else:
            del data['inputs']

        outputs = []
        for output in data['outputs']:
            value = output['value']
            script = base64.b64decode(output['script'])
            token_data = output['token_data']
            outputs.append(TxOutput(value, script, token_data))
        if len(outputs) > 0:
            data['outputs'] = outputs

        tokens = [bytes.fromhex(uid) for uid in data['tokens']]
        if len(tokens) > 0:
            data['tokens'] = tokens
        else:
            del data['tokens']

        if 'aux_pow' in data:
            data['aux_pow'] = BitcoinAuxPow.from_bytes(bytes.fromhex(data['aux_pow']))

        data['storage'] = self
        cls = TxVersion(data['version']).get_cls()
        tx = cls(**data)
        tx.update_hash()
        assert tx.hash is not None
        assert tx.hash == hash_bytes, 'Hashes differ: {} != {}'.format(tx.hash.hex(), hash_bytes.hex())
        return tx

    def _get_transaction(self, hash_bytes: bytes) -> 'BaseTransaction':
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

    def get_all_transactions(self) -> Iterator['BaseTransaction']:
        tx: Optional['BaseTransaction']

        for f in glob.iglob(os.path.join(self.tx_path, '*/*')):
            match = self.re_pattern.match(os.path.basename(f))
            if match:
                hash_bytes = bytes.fromhex(match.groups()[0])
                tx = self.get_transaction(hash_bytes)
                assert tx is not None
                yield tx

    def get_count_tx_blocks(self) -> int:
        files = [
            f for f in glob.iglob(os.path.join(self.tx_path, '*/*')) if self.re_pattern.match(os.path.basename(f))
        ]
        return len(files)

    def add_value(self, key: str, value: str) -> None:
        filepath = os.path.join(self.attributes_path, key)
        with open(filepath, 'w') as json_file:
            json_file.write(value)

    def remove_value(self, key: str) -> None:
        filepath = os.path.join(self.attributes_path, key)
        try:
            os.unlink(filepath)
        except FileNotFoundError:
            pass

    def get_value(self, key: str) -> Optional[str]:
        filepath = os.path.join(self.attributes_path, key)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as json_file:
                return json_file.read()
        else:
            return None
