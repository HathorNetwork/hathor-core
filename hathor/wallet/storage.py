from hathor.wallet.data import WalletData
import json
import os
import re


class WalletStorage:
    def __init__(self, path=''):
        self.path = path

    def generate_filepath(self, hash_hex):
        filename = 'tx_received_{}.json'.format(hash_hex)
        filepath = os.path.join(self.path, filename)
        return filepath

    def save_data(self, wallet_data):
        data = self.serialize_data(wallet_data)
        filepath = self.generate_filepath(wallet_data.tx_id.hex())
        with open(filepath, 'w') as json_file:
            json_file.write(json.dumps(data, indent=4))

    def get_data(self, tx_id):
        filepath = self.generate_filepath(tx_id)
        with open(filepath, 'r') as json_file:
            json_data = json.loads(json_file.read())
            return self.load_data(json_data)

    def serialize_data(self, obj):
        ret = {}

        ret['tx_id'] = obj.tx_id.hex()
        ret['index'] = obj.index

        return ret

    def load_data(self, data):
        return WalletData(bytes.fromhex(data['tx_id']), data['index'])

    def get_all_tx_received(self):
        received_tx = []
        path = self.path or '.'  # if self.path is '' we have to put as '.'
        files = os.listdir(path)
        pattern = r'tx_received_[\dabcdef]{64}\.json'

        for f in files:
            if re.match(pattern, f):
                wallet_data = self.get_data(f[12:-5])
                received_tx.append(wallet_data)

        return received_tx
