from hathor.wallet.generate_keys import generate_keys, load_keys
from hathor.wallet.storage import WalletStorage
from hathor.wallet.data import WalletData
from hathor.transaction.storage import default_transaction_storage
from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist
from hathor.transaction.base_transaction import Input, Output
from hathor.transaction.transaction import Transaction
from hathor.util import get_input_data, get_public_key_bytes, get_address_from_public_key
import os


class Wallet:

    def __init__(self, dir='', create_keys=False, storage=None, transaction_storage=None):
        keys_file = os.path.join(dir, 'keys.json')
        if create_keys:
            # Create new keys
            self.private_key, self.public_key = generate_keys(keys_file)
        else:
            # Load keys from disk
            self.private_key, self.public_key = load_keys(keys_file)

        self.dir = dir
        self.storage = storage or WalletStorage(path=self.dir)
        self.transaction_storage = transaction_storage or default_transaction_storage()

    def prepare_transaction_without_inputs(self, outputs):
        """
            Outputs: array of dict {'address': b'address', 'value': 0}
        """
        amount = sum([output['value'] for output in outputs])
        inputs = self.get_inputs_from_amount(amount)
        return self.prepare_transaction_with_inputs(inputs, outputs)

    def prepare_transaction_with_inputs(self, inputs, outputs):
        """
            Inputs: array of dict {'tx_id': b'tx_id', 'index': 0}
            Outputs: array of dict {'address': b'address', 'value': 0}
        """
        # TODO how to get unconfirmed transactions (parents)?
        # TODO where should we do it?
        # parents = self.storage.get_latest_transactions()
        # parents_hash = [p.hash for p in parents]

        tx_inputs = []
        for i in inputs:
            input_data = get_input_data(i['tx_id'], self.private_key, self.public_key)
            tx_inputs.append(Input(i['tx_id'], i['index'], input_data))

        tx_outputs = []
        for o in outputs:
            tx_outputs.append(Output(o['value'], o['address']))

        tx_outputs = self.handle_return_amount(tx_inputs, tx_outputs)

        return Transaction(inputs=tx_inputs, outputs=tx_outputs, storage=self.transaction_storage)

    def handle_return_amount(self, inputs, outputs):
        sum_outputs = sum([output.value for output in outputs])

        sum_inputs = 0
        for tx_input in inputs:
            tx_obj = self.transaction_storage.get_transaction_by_hash_bytes(tx_input.tx_id)
            sum_inputs += tx_obj.outputs[tx_input.index].value

        if sum_inputs < sum_outputs:
            # TODO raise exception I dont have this amount of tokens
            pass
        elif sum_inputs > sum_outputs:
            difference = sum_inputs - sum_outputs

            public_key_bytes = get_public_key_bytes(self.public_key)
            address = get_address_from_public_key(public_key_bytes)
            new_output = Output(difference, address)
            outputs.append(new_output)

        return outputs

    def get_inputs_from_amount(self, amount):
        inputs_tx = []
        total_inputs_amount = 0

        received_tx = self.storage.get_all_tx_received()
        for received in received_tx:
            try:
                metadata = self.transaction_storage.get_metadata_by_hash_bytes(received.tx_id)
                if received.index in metadata.spent_outputs:
                    continue
            except TransactionMetadataDoesNotExist:
                pass

            tx_obj = self.transaction_storage.get_transaction_by_hash_bytes(received.tx_id)
            inputs_tx.append({'tx_id': received.tx_id, 'index': received.index})
            total_inputs_amount += tx_obj.outputs[received.index].value

            if total_inputs_amount >= amount:
                break

        if total_inputs_amount < amount:
            # TODO raise exception I dont have this amount of tokens
            pass

        return inputs_tx

    def transaction_received(self, tx):
        public_key_bytes = get_public_key_bytes(self.public_key)
        address = get_address_from_public_key(public_key_bytes)

        for index, output in enumerate(tx.outputs):
            if output.script == address:
                wd = WalletData(tx.hash, index)
                self.storage.save_data(wd)
                break
