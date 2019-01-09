from twisted.web import resource

from hathor.api_util import set_cors, render_options, get_missing_params_msg
from hathor.transaction import Transaction, TxOutput, TxInput
from hathor.transaction.scripts import P2PKH, NanoContractMatchValues

import json
import base58
import base64

PARAMS_POST = ['values', 'fallback_address', 'oracle_pubkey_hash',
               'oracle_data_id', 'total_value', 'input_value']

PARAMS_PUT = ['hex_tx', 'new_values', 'input_value']


class NanoContractMatchValueResource(resource.Resource):
    """ Implements a web server API to create/update MatchValue nano contract txs.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Creates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        values: List[{'address', 'value'}], with bet address and value
        fallback_address: if none of the addresses above is the winner, this address
                          can execute the contract
        oracle_pubkey_hash: oracle's public key hashed
        oracle_data_id: oracle's id about this nano contract
        total_value: nano contract total value
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS_POST:
            if param not in data:
                return get_missing_params_msg(param)

        value_dict = {}
        for item in data['values']:
            value_dict[base58.b58decode(item['address'])] = item['value']

        fallback_address = base58.b58decode(data['fallback_address']) if data['fallback_address'] else b'\x00'
        min_timestamp = data['min_timestamp'] if data.get('min_timestamp') else int(self.manager.reactor.seconds())

        nano_contract = NanoContractMatchValues(
            base64.b64decode(data['oracle_pubkey_hash']),
            min_timestamp,
            data['oracle_data_id'].encode('utf-8'),
            value_dict,
            fallback_address
        )

        tx_outputs = []
        tx_outputs.append(TxOutput(data['total_value'], nano_contract.create_output_script()))

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(data['input_value'])
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, data['input_value'])
        if change_tx:
            tx_outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))
        tx_inputs = [TxInput(txin.tx_id, txin.index, b'') for txin in inputs]

        tx = Transaction(inputs=tx_inputs, outputs=tx_outputs)

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

    def render_PUT(self, request):
        """ Updates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        hex_tx: tx being updated, in hex value
        new_values: List[{'address', 'value'}], with bet address and value
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'PUT')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS_PUT:
            if param not in data:
                return get_missing_params_msg(param)

        tx_bytes = bytes.fromhex(data['hex_tx'])
        tx = Transaction.create_from_struct(tx_bytes)

        new_value_dict = {}
        for item in data['new_values']:
            new_value_dict[base58.b58decode(item['address'])] = item['value']

        input_value = data['input_value']

        tx_outputs = []
        nano_contract = None
        for _output in tx.outputs:
            _nano_contract = NanoContractMatchValues.parse_script(_output.script)
            if _nano_contract:
                total_value = _output.value
                nano_contract = _nano_contract
            else:
                tx_outputs.append(_output)

        if not nano_contract:
            return json.dumps({'success': False, 'message': 'Nano contract not found'}).encode('utf-8')

        for address, value in new_value_dict.items():
            nano_contract.value_dict[address] = value

        tx.outputs = tx_outputs

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(input_value)
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, input_value)
        if change_tx:
            tx.outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))

        tx.outputs.insert(0, TxOutput(total_value, nano_contract.create_output_script()))

        [tx.inputs.append(TxInput(txin.tx_id, txin.index, b'')) for txin in inputs]

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request, 'GET, POST, PUT, OPTIONS')
