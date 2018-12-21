from twisted.web import resource

from hathor.api_util import set_cors, render_options, get_missing_params_msg
from hathor.transaction import Transaction, TxOutput, TxInput
from hathor.transaction.scripts import create_output_script, NanoContractMatchInterval

import json
import base58
import base64

PARAMS_POST = ['address', 'interval', 'oracle_pubkey_hash',
               'oracle_data_id', 'total_value', 'input_value']

PARAMS_PUT = ['total', 'items', 'oracle_data_id', 'oracle_pubkey_hash']

PARAMS_GET = ['start_value', 'end_value', 'amount']


class NanoContractMatchIntervalResource(resource.Resource):
    """ Implements a web server API to create/update MatchInterval nano contract txs.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """Receive inputs and outputs from participants, validate and return ordered
        contract info and total contract amount.

        # TODO update docstring
        Post data should be a json with the following items:
        address: bet address
        interval: Tuple(start, end)
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
            return 'Unable to decode JSON'.encode('utf-8')

        first_item = list(filter(lambda k: k['start_value'] is None, data))
        if len(first_item) == 0:
            return json.dumps({'success': False, 'message': 'Missing initial interval'}).encode('utf-8')
        elif len(first_item) > 1:
            return json.dumps({'success': False, 'message': 'Overlaping initial interval'}).encode('utf-8')
        else:
            first_item = first_item[0]
            data.remove(first_item)

        last_item = list(filter(lambda k: k['end_value'] is None, data))
        if len(last_item) == 0:
            return json.dumps({'success': False, 'message': 'Missing final interval'}).encode('utf-8')
        elif len(last_item) > 1:
            return json.dumps({'success': False, 'message': 'Overlaping final interval'}).encode('utf-8')
        else:
            last_item = last_item[0]
            data.remove(last_item)

        sorted_list = sorted(data, key=lambda k: k['start_value'])
        sorted_list.append(last_item)
        sorted_list.insert(0, first_item)

        # make sure intervals are continuous
        last_end = None
        for item in sorted_list:
            if last_end != item['start_value']:
                return json.dumps({'success': False, 'message': 'Non continuous intervals'}).encode('utf-8')
            last_end = item['end_value']

        # get amount staked by each participant and total amount
        total_amount = 0
        for item in sorted_list:
            output_amount = sum([d['amount'] for d in item['outputs']])
            input_amount = 0
            for _input in item['inputs']:
                tx = self.manager.tx_storage.get_transaction(bytes.fromhex(_input['tx_id']))
                # TODO check tx and output exists
                input_amount += tx.outputs[_input['index']].value
            item['amount'] = input_amount - output_amount
            total_amount += item['amount']

        ret = {'success': True, 'total': total_amount, 'items': sorted_list}
        return json.dumps(ret).encode('utf-8')

    def render_PUT(self, request):
        """Receive all contract info (inputs, outputs and oracle info) and return the transaction

        # TODO update docstring
        Put data should be a json with the following items:
        hex_tx: tx being updated, in hex value
        new_address: bet address
        new_interval: Tuple(start, end)
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'PUT')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return 'Unable to decode JSON'.encode('utf-8')

        for param in PARAMS_PUT:
            if param not in data:
                return get_missing_params_msg(param)

        min_timestamp = data['min_timestamp'] if data.get('min_timestamp') else int(self.manager.reactor.seconds())
        oracle_pubkey_hash = base64.b64decode(data['oracle_pubkey_hash'])
        oracle_data_id = data['oracle_data_id'].encode('utf-8')

        pubkey_list = [base58.b58decode(item['address']) for item in data['items']]
        value_list = [item['start_value'] for item in data['items'][1:]]

        nc = NanoContractMatchInterval(oracle_pubkey_hash, min_timestamp, oracle_data_id, pubkey_list, value_list)

        inputs = []
        outputs = [TxOutput(data['total'], nc.create_output_script())]
        for item in data['items']:
            for _output in item['outputs']:
                outputs.append(TxOutput(_output['amount'], create_output_script(base58.b58decode(_output['address']))))
            for _input in item['inputs']:
                inputs.append(TxInput(bytes.fromhex(_input['tx_id']), _input['index'], b''))

        tx = Transaction(inputs=inputs, outputs=outputs)

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

#    def render_GET(self, request):
#        """ Gets the input data for a participant in a MatchInterval nano contract
#
#        Expects 'start_value', 'end_value' and 'amount' as GET parameters
#
#        :rtype: string (json)
#        """
#        request.setHeader(b'content-type', b'application/json; charset=utf-8')
#        set_cors(request, 'GET')
#
#        params = {}
#        for param in PARAMS_GET:
#            value = request.args.get(param.encode('utf-8'))
#            try:
#                params[param] = decode_int(value)
#            except ValueError:
#                return get_missing_params_msg(param)
#
#        if not params['amount']:
#            return get_missing_params_msg('amount')
#        if not params['start_value'] and not params['end_value']:
#            return get_missing_params_msg('start_value or end_value')
#
#        inputs_tx, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(params['amount'])
#        inputs = []
#        for _input in inputs_tx:
#            inputs.append({'tx_id': _input.tx_id.hex(), 'index': _input.index})
#
#        outputs = []
#        if total_inputs_amount - params['amount'] > 0:
#            addr = self.manager.wallet.get_unused_address(mark_as_used=True)
#            outputs.append({'address': addr, 'amount': (total_inputs_amount - params['amount'])})
#
#        address = self.manager.wallet.get_unused_address(mark_as_used=True)
#
#        ret = {'address': address,
#               'start_value': params['start_value'],
#               'end_value': params['end_value'],
#               'inputs': inputs,
#               'outputs': outputs
#               }
#        return json.dumps(ret).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request, 'GET, POST, PUT, OPTIONS')


def decode_int(value):
    if not value or value[0] == b'':
        return None
    return int(value[0].decode('utf-8'))
