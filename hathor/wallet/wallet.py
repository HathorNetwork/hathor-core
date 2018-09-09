import os
import json
import base58
from collections import namedtuple
from hathor.wallet.keypair import KeyPair
from hathor.wallet.exceptions import WalletOutOfSync
from hathor.transaction import TxInput, TxOutput
from hathor.crypto.util import get_input_data, decode_input_data, \
                               get_address_b58_from_public_key_bytes, \
                               get_address_b58_from_bytes

# TODO add timestamp
UnspentTx = namedtuple('UnspentTx', ['tx_id', 'index', 'value', 'timestamp'])
# tx_id is the tx spending the output
# from_tx_id is the tx where we received the tokens
# from_index is the index in the above tx
SpentTx = namedtuple('SpentTx', ['tx_id', 'from_tx_id', 'from_index', 'value', 'timestamp'])

WalletInputInfo = namedtuple('WalletInputInfo', ['tx_id', 'index', 'private_key'])
WalletOutputInfo = namedtuple('WalletOutputInfo', ['address', 'value'])


class Wallet(object):
    def __init__(self, keys=None, directory='./', filename='keys.json'):
        """ A wallet will hold key pair objects and the unspent and
        spent transactions associated with the keys.

        All files will be stored in the same directory, and it should
        only contain wallet associated files.

        keys: set of KeyPair objects (b58_address => KeyPair)
        directory: location where to store associated files
        filename: name of the keys file, relative to directory
        """
        self.filepath = os.path.join(directory, filename)
        self.keys = keys or {}
        self.unused_keys = set(key.get_address_b58() for key in self.keys.values() if not key.used)
        self.unspent_txs = {}
        self.spent_txs = []
        self.balance = 0

    def read_keys_from_file(self):
        """Reads the keys from file and updates the keys dictionary

        Uses the directory and filename specified in __init__
        """
        new_keys = {}
        with open(self.filepath, 'r') as json_file:
            json_data = json.loads(json_file.read())
            for data in json_data:
                keypair = KeyPair.from_json(data)
                new_keys[keypair.get_address_b58()] = keypair

        self.keys.update(new_keys)

    def _write_keys_to_file(self):
        data = [keypair.to_json() for keypair in self.keys.values()]
        with open(self.filepath, 'w') as json_file:
            json_file.write(json.dumps(data, indent=4))

    def get_unused_address(self, mark_as_used=True):
        updated = False
        if len(self.unused_keys) == 0:
            self.generate_keys()
            updated = True

        if mark_as_used:
            address = self.unused_keys.pop()
            keypair = self.keys[address]
            keypair.used = True
            updated = True
        else:
            address = next(iter(self.unused_keys))

        if updated:
            self._write_keys_to_file()

        return address

    def get_unused_address_bytes(self, mark_as_used=True):
        address_str = self.get_unused_address(mark_as_used)
        return address_str.encode('utf-8')

    def generate_keys(self, count=10):
        for _ in range(count):
            key = KeyPair()
            address = key.get_address_b58()
            self.keys[address] = key
            self.unused_keys.add(address)

    def prepare_transaction(self, cls, inputs, outputs):
        """Prepares the tx inputs and outputs.

        Can be used to create blocks by passing empty list to inputs.

        cls: either Transaction or Block
        inputs: array of WalletInputInfo tuple
        outputs: array of WalletOutputInfo tuple
        """
        tx_inputs = []
        for i in inputs:
            input_data = get_input_data(i.tx_id, i.private_key, i.private_key.public_key())
            tx_inputs.append(TxInput(i.tx_id, i.index, input_data))

        tx_outputs = []
        for o in outputs:
            tx_outputs.append(TxOutput(o.value, o.address))

        return cls(inputs=tx_inputs, outputs=tx_outputs)

    def prepare_transaction_incomplete_inputs(self, cls, inputs, outputs):
        """Uses the function above to prepare transaction.

        The difference is that the inputs argument does not contain the private key
        corresponding to it.

        Consider the wallet UI scenario: the user will see all unspent txs and can select
        which ones he wants to use as input, but the wallet is responsible for managing
        the keys, so he won't be able to send the inputs with the corresponding key.
        """
        new_inputs = []
        for _input in inputs:
            found = False
            for address_b58, utxo_list in self.unspent_txs.items():
                for utxo in utxo_list:
                    if _input.tx_id == utxo.tx_id and _input.index == utxo.index:
                        new_inputs.insert(
                            0,
                            WalletInputInfo(_input.tx_id, _input.index, self.keys[address_b58].private_key)
                        )
                        found = True
            if not found:
                raise WalletOutOfSync

        return self.prepare_transaction(cls, new_inputs, outputs)

    def prepare_transaction_compute_inputs(self, cls, outputs):
        """Calculates de inputs given the outputs. Handles change.

        cls: either Transaction or Block
        outputs: array of WalletOutputInfo tuple
        """
        amount = sum(output.value for output in outputs)
        inputs, total_inputs_amount = self.get_inputs_from_amount(amount)
        change_tx = self.handle_change_tx(total_inputs_amount, outputs)
        if change_tx:
            # change is usually the first output
            outputs.insert(0, change_tx)
        return self.prepare_transaction(cls, inputs, outputs)

    def handle_change_tx(self, sum_inputs, outputs):
        """Creates an output transaction with the change value
        """
        sum_outputs = sum([output.value for output in outputs])

        if sum_inputs > sum_outputs:
            difference = sum_inputs - sum_outputs
            address_b58 = self.get_unused_address()
            address = base58.b58decode(address_b58)
            new_output = WalletOutputInfo(address, difference)
            return new_output
        return None

    def get_inputs_from_amount(self, amount):
        """Creates inputs from our pool of unspent tx given a value

        This is a very simple algorithm, so it does not try to find the best combination
        of inputs.
        """
        inputs_tx = []
        total_inputs_amount = 0

        for address_b58, utxo_list in self.unspent_txs.items():
            for utxo in utxo_list:
                inputs_tx.append(WalletInputInfo(utxo.tx_id, utxo.index, self.keys[address_b58].private_key))
                total_inputs_amount += utxo.value

                if total_inputs_amount >= amount:
                    break

            if total_inputs_amount >= amount:
                break

        if total_inputs_amount < amount:
            # TODO raise exception I dont have this amount of tokens
            pass

        return inputs_tx, total_inputs_amount

    def on_new_tx(self, tx):
        """Checks the inputs and outputs of a transaction for matching keys.

        If an output matches, will add it to the unspent_txs dict.
        If an input matches, removes from unspent_txs dict and adds to spent_txs list.
        """
        updated = False

        # check outputs
        for index, output in enumerate(tx.outputs):
            # address this tokens were sent to
            output_address = get_address_b58_from_bytes(output.script)
            if output_address in self.keys.keys():
                # this wallet received tokens
                utxo = UnspentTx(tx.hash, index, output.value, tx.timestamp)
                utxo_list = self.unspent_txs.pop(output_address, [])
                utxo_list.append(utxo)
                self.unspent_txs[output_address] = utxo_list
                # mark key as used
                self.keys[output_address].used = True
                self.balance += output.value
                updated = True

        # check inputs
        for index, _input in enumerate(tx.inputs):
            (_, _, _, public_key) = decode_input_data(_input.data)
            input_address = get_address_b58_from_public_key_bytes(public_key)
            if input_address in self.keys.keys():
                # this wallet spent tokens
                # remove from unspent_txs
                utxo_list = self.unspent_txs.pop(input_address)
                list_index = -1
                for i, utxo in enumerate(utxo_list):
                    if utxo.tx_id == _input.tx_id and utxo.index == _input.index:
                        list_index = i
                        break
                if list_index == -1:
                    # the wallet does not have the output referenced by this input
                    raise WalletOutOfSync
                old_utxo = utxo_list.pop(list_index)
                if len(utxo_list) > 0:
                    self.unspent_txs[input_address] = utxo_list
                # add to spent_txs
                spent = SpentTx(tx.hash, _input.tx_id, _input.index, old_utxo.value, tx.timestamp)
                self.spent_txs.append(spent)
                self.balance -= old_utxo.value
                updated = True

        if updated:
            # TODO update disk file
            pass

    def get_history(self, count=10, page=1):
        history = []
        unspent = self.unspent_txs.values()
        for obj in unspent:
            history += obj

        history += self.spent_txs
        ordered_history = sorted(history, key=lambda el: el.timestamp, reverse=True)

        total = len(ordered_history)
        start_index = (page - 1) * count
        end_index = start_index + count

        return ordered_history[start_index:end_index], total
