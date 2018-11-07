from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.transaction_metadata import TransactionMetadata

import json
import os
import re
import base64


class TransactionCompactStorage(TransactionStorage):
    """This storage saves tx and metadata in the same file.

    It also uses JSON format. Saved file is of format {'tx': {...}, 'meta': {...}}
    """
    def __init__(self, path='./', with_index=True):
        self.mkdir_if_needed(path)
        self.path = path
        super().__init__(with_index=with_index)

    def mkdir_if_needed(self, path):
        if not os.path.isdir(path):
            os.makedirs(path)

    def generate_filepath(self, hash_hex):
        filename = 'tx_{}.json'.format(hash_hex)
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
            json_file.write(json.dumps(data))

    def load_from_json(self, filepath, error):
        if os.path.isfile(filepath):
            with open(filepath, 'r') as json_file:
                dict_data = json.loads(json_file.read())
                return dict_data
        else:
            raise error

    def save_transaction(self, tx):
        super().save_transaction(tx)
        self._save_transaction(tx)

    def _save_transaction(self, tx):
        data = {}
        data['tx'] = tx.to_json()
        meta = getattr(tx, '_metadata', None)
        if meta:
            data['meta'] = tx._metadata.to_json()
        filepath = self.generate_filepath(data['tx']['hash'])
        self.save_to_json(filepath, data)

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis

        hash_hex = hash_bytes.hex()
        filepath = self.generate_filepath(hash_hex)
        data = self.load_from_json(filepath, TransactionDoesNotExist(hash_hex))
        tx = self.load(data['tx'])
        if 'meta' in data.keys():
            meta = TransactionMetadata.create_from_json(data['meta'])
            tx._metadata = meta
        return tx

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def load(self, data):
        from hathor.transaction.transaction import Transaction
        from hathor.transaction.block import Block
        from hathor.transaction.base_transaction import Output, Input

        nonce = data['nonce']
        timestamp = data['timestamp']
        height = data['height']
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
            inputs.append(Input(tx_id, index, input_data))

        outputs = []
        for output in data['outputs']:
            value = output['value']
            script = base64.b64decode(output['script'])
            outputs.append(Output(value, script))

        kwargs = {
            'nonce': nonce,
            'timestamp': timestamp,
            'version': version,
            'height': height,
            'weight': weight,
            'outputs': outputs,
            'parents': parents,
            'storage': self,
        }

        if len(inputs) == 0:
            tx = Block(**kwargs)
        else:
            kwargs['inputs'] = inputs
            tx = Transaction(**kwargs)
        tx.update_hash()
        assert tx.hash == hash_bytes, 'Hashes differ: {} != {}'.format(tx.hash.hex(), hash_bytes.hex())
        return tx

    def save_metadata(self, tx):
        # genesis txs and metadata are kept in memory
        if not tx.is_genesis:
            self._save_transaction(tx)

    def _get_metadata_by_hash(self, hash_hex):
        tx = self.get_transaction_by_hash(hash_hex)
        meta = getattr(tx, '_metadata', None)
        if meta:
            return meta
        else:
            raise TransactionMetadataDoesNotExist

    def get_all_transactions(self):
        for tx in self.get_all_genesis():
            yield tx

        path = self.path
        pattern = r'tx_[\dabcdef]{64}\.json'
        re_pattern = re.compile(pattern)

        with os.scandir(path) as it:
            for f in it:
                if re_pattern.match(f.name):
                    # TODO Return a proxy that will load the transaction only when it is used.
                    data = self.load_from_json(f.path, TransactionDoesNotExist())
                    tx = self.load(data['tx'])
                    if 'meta' in data.keys():
                        meta = TransactionMetadata.create_from_json(data['meta'])
                        tx._metadata = meta
                    yield tx

    def get_count_tx_blocks(self):
        genesis_len = len(self.get_all_genesis())
        path = self.path
        files = os.listdir(path)
        return len(files) + genesis_len
