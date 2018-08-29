import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class TransactionJSONStorage(object):
    def save_transaction(self, tx):
        print(' ######## ')
        data = self.serialize(tx)
        print(data)
        with open('tx_{}.json'.format(data['hash']), 'w') as json_file:
            json_file.write(json.dumps(data, indent=4))

    def get_transaction_by_hash(self, hash_bytes):
        hash_hex = hash_bytes.hex()
        # TODO Check if file exists.
        with open('tx_{}.json'.format(hash_hex), 'r') as json_file:
            dict_data = json.loads(json_file.read())
            return self.load(dict_data)

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
        for input_ in tx.inputs:
            data_input = {}
            data_input['tx_id'] = input_.tx_id.hex()
            data_input['index'] = input_.index
            data_input['signature'] = base64.b64encode(input_.signature).decode('utf-8')
            serialized_key = input_.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            data_input['public_key'] = base64.b64encode(serialized_key).decode('utf-8')
            data['inputs'].append(data_input)

        data['outputs'] = []
        for output in tx.outputs:
            data_output = {}
            # TODO use base58 and ripemd160
            data_output['address'] = output.address.hex()
            data_output['amount'] = output.amount
            data['outputs'].append(data_output)

        return data

    def load(self, data):
        from hathor.transaction import Transaction, Output, Input

        nonce = data['nonce']
        timestamp = data['timestamp']
        version = data['version']
        weight = data['weight']
        hash_ = bytes.fromhex(data['hash'])

        parents = []
        for parent in data['parents']:
            parents.append(bytes.fromhex(parent))

        inputs = []
        for input_ in data['inputs']:
            tx_id = bytes.fromhex(input_['tx_id'])
            index = input_['index']
            signature = base64.b64decode(input_['signature'])
            serialized_key = base64.b64decode(input_['public_key'])
            public_key = serialization.load_der_public_key(
                serialized_key,
                backend=default_backend()
            )
            inputs.append(Input(tx_id, index, signature, public_key))

        outputs = []
        for output in data['outputs']:
            # TODO use base58 and ripemd160
            address = bytes.fromhex(output['address'])
            amount = output['amount']
            outputs.append(Output(address, amount))

        return Transaction(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            hash=hash_,
            storage=self
        )
