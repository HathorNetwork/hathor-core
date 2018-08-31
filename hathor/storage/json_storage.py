import json
import os
import base64
from hathor.storage.transaction_storage import TransactionStorage
from hathor.storage.exceptions import TransactionDoesNotExist, TransactionMetadataDoesNotExist


class TransactionJSONStorage(TransactionStorage):
    def __init__(self, path=''):
        self.path = path

    def generate_filepath(self, hash_hex):
        filename = 'tx_{}.json'.format(hash_hex)
        filepath = os.path.join(self.path, filename)
        return filepath

    def generate_metadata_filepath(self, hash_hex):
        filename = 'tx_{}_metadata.json'.format(hash_hex)
        filepath = os.path.join(self.path, filename)
        return filepath

    def transaction_exists_by_hash_bytes(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        filepath = self.generate_filepath(hash_hex)
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

    def save_transaction(self, tx):
        data = self.serialize(tx)
        filepath = self.generate_filepath(data['hash'])
        self.save_to_json(filepath, data)

    def get_transaction_by_hash_bytes(self, hash_bytes):
        genesis = self.get_genesis_by_hash_bytes(hash_bytes)
        if genesis:
            return genesis

        hash_hex = hash_bytes.hex()
        filepath = self.generate_filepath(hash_hex)
        data = self.load_from_json(filepath, TransactionDoesNotExist)
        return self.load(data)

    def get_transaction_by_hash(self, hash_hex):
        hash_bytes = bytes.fromhex(hash_hex)
        return self.get_transaction_by_hash_bytes(hash_bytes)

    def serialize(self, tx):
        data = {}
        data['hash'] = tx.hash.hex()
        data['nonce'] = tx.nonce
        data['timestamp'] = tx.timestamp
        data['version'] = tx.version
        data['weight'] = tx.weight

        data['parents'] = []
        for parent in tx.parents:
            data['parents'].append(parent.hex())

        data['inputs'] = []
        # Blocks don't have inputs
        if not tx.is_block:
            for input_tx in tx.inputs:
                data_input = {}
                data_input['tx_id'] = input_tx.tx_id.hex()
                data_input['index'] = input_tx.index
                data_input['data'] = base64.b64encode(input_tx.data).decode('utf-8')
                data['inputs'].append(data_input)

        data['outputs'] = []
        for output in tx.outputs:
            data_output = {}
            # TODO use base58 and ripemd160
            data_output['value'] = output.value
            data_output['script'] = base64.b64encode(output.script).decode('utf-8')
            data['outputs'].append(data_output)

        return data

    def load(self, data):
        from hathor.transaction.transaction import Transaction
        from hathor.transaction.block import Block
        from hathor.transaction.base_transaction import Output, Input

        nonce = data['nonce']
        timestamp = data['timestamp']
        version = data['version']
        weight = data['weight']
        hash_hex = bytes.fromhex(data['hash'])

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
            'weight': weight,
            'outputs': outputs,
            'parents': parents,
            'hash': hash_hex,
            'storage': self,
        }

        if len(inputs) == 0:
            return Block(**kwargs)
        else:
            kwargs['inputs'] = inputs
            return Transaction(**kwargs)

    def save_metadata(self, metadata):
        data = self.serialize_metadata(metadata)
        filepath = self.generate_metadata_filepath(data['hash'])
        self.save_to_json(filepath, data)

    def get_metadata(self, hash_hex):
        filepath = self.generate_metadata_filepath(hash_hex)
        data = self.load_from_json(filepath, TransactionMetadataDoesNotExist)
        return self.load_metadata(data)

    def serialize_metadata(self, metadata):
        data = {}
        data['hash'] = metadata.hash.hex()
        data['unspent_outputs'] = metadata.unspent_outputs
        return data

    def load_metadata(self, data):
        from hathor.storage.transaction_metadata import TransactionMetadata
        tm = TransactionMetadata()
        tm.hash = bytes.fromhex(data['hash'])
        tm.unspent_outputs = data['unspent_outputs']
        return tm
