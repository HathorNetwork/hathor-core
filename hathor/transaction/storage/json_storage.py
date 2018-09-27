from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist
from hathor.transaction.transaction_metadata import TransactionMetadata

import json
import os
import re
import base64


class TransactionJSONStorage(TransactionStorage):
    def __init__(self, path='./'):
        self.mkdir_if_needed(path)
        self.path = path
        super().__init__()

    def mkdir_if_needed(self, path):
        if not os.path.isdir(path):
            os.makedirs(path)

    def generate_filepath(self, hash_hex):
        filename = 'tx_{}.json'.format(hash_hex)
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
        data = tx.to_json()
        filepath = self.generate_filepath(data['hash'])
        self.save_to_json(filepath, data)
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

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis

        hash_hex = hash_bytes.hex()
        filepath = self.generate_filepath(hash_hex)
        data = self.load_from_json(filepath, TransactionDoesNotExist(hash_hex))
        return self.load(data)

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
        data = {}
        data['hash'] = metadata.hash.hex()
        data['spent_outputs'] = list(metadata.spent_outputs)
        data['accumulated_weight'] = metadata.accumulated_weight
        return data

    def load_metadata(self, data):
        tm = TransactionMetadata()
        tm.hash = bytes.fromhex(data['hash'])
        tm.spent_outputs = set(data['spent_outputs'])
        tm.accumulated_weight = data['accumulated_weight']
        return tm

    def get_all_transactions(self):
        from hathor.transaction.genesis import genesis_transactions
        for tx in genesis_transactions(self):
            yield tx

        path = self.path
        files = os.listdir(path)
        pattern = r'tx_[\dabcdef]{64}\.json'

        for f in files:
            if re.match(pattern, f):
                # TODO Return a proxy that will load the transaction only when it is used.
                hash_hex = f[3:-5]
                transaction = self.get_transaction_by_hash(hash_hex)
                yield transaction

    def get_count_tx_blocks(self):
        from hathor.transaction.genesis import genesis_transactions
        genesis_len = len([tx for tx in genesis_transactions(self)])
        path = self.path
        files = os.listdir(path)
        return len(files) + genesis_len
