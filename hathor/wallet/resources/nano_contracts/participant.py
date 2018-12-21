from twisted.web import resource

from hathor.api_util import set_cors, render_options, get_missing_params_msg
from hathor.transaction import Transaction
from hathor.transaction.scripts import P2PKH

import re
import json
import base64

# PARAMS_POST = ['address', 'interval', 'oracle_pubkey_hash',
#               'oracle_data_id', 'total_value', 'input_value']

PARAMS_PUT = ['hex_tx']

PARAMS_POST = ['start_value', 'end_value', 'amount']


class NanoContractParticipantResource(resource.Resource):
    """ Implements a web server API to create/update MatchInterval nano contract txs.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

#    def render_POST(self, request):
#        """ Creates a nano contract tx and returns it in hexadecimal format.
#
#        # TODO update docstring
#        Post data should be a json with the following items:
#        address: bet address
#        interval: Tuple(start, end)
#        oracle_pubkey_hash: oracle's public key hashed
#        oracle_data_id: oracle's id about this nano contract
#        total_value: nano contract total value
#        input_value: amount this wallet should stake in the nano contract
#
#        :rtype: string (json)
#        """
#        request.setHeader(b'content-type', b'application/json; charset=utf-8')
#        set_cors(request, 'POST')
#
#        try:
#            data = json.loads(request.content.read().decode('utf-8'))
#        except json.JSONDecodeError:
#            return 'Unable to decode JSON'.encode('utf-8')
#
#        first_item = list(filter(lambda k: k['start_value'] is None, data))
#        if len(first_item) == 0:
#            return json.dumps({'success': False, 'message': 'Missing initial interval'}).encode('utf-8')
#        elif len(first_item) > 1:
#            return json.dumps({'success': False, 'message': 'Overlaping initial interval'}).encode('utf-8')
#        else:
#            first_item = first_item[0]
#            data.remove(first_item)
#
#        last_item = list(filter(lambda k: k['end_value'] is None, data))
#        if len(last_item) == 0:
#            return json.dumps({'success': False, 'message': 'Missing final interval'}).encode('utf-8')
#        elif len(last_item) > 1:
#            return json.dumps({'success': False, 'message': 'Overlaping final interval'}).encode('utf-8')
#        else:
#            last_item = last_item[0]
#            data.remove(last_item)
#
#        sorted_list = sorted(data, key=lambda k: k['start_value'])
#        sorted_list.append(last_item)
#        sorted_list.insert(0, first_item)
#
#        # make sure intervals are continuous
#        last_end = None
#        for item in sorted_list:
#            if last_end != item['start_value']:
#                return json.dumps({'success': False, 'message': 'Non continuous intervals'}).encode('utf-8')
#            last_end = item['end_value']
#
#        # get amount staked by each participant and total amount
#        total_amount = 0
#        for item in sorted_list:
#            output_amount = sum([d['amount'] for d in item['outputs']])
#            input_amount = 0
#            for _input in item['inputs']:
#                tx = self.manager.tx_storage.get_transaction(bytes.fromhex(_input['tx_id']))
#                # TODO check tx and output exists
#                input_amount += tx.outputs[_input['index']].value
#            item['amount'] = input_amount - output_amount
#            total_amount += item['amount']
#
#        ret = {'success': True, 'total': total_amount, 'items': sorted_list}
#        return json.dumps(ret).encode('utf-8')
#
    def render_PUT(self, request):
        """ Sign inputs

        PUT data should be a json with the following items:
        hex_tx: transaction in hexadecimal

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

        pattern = r'[a-fA-F\d]+'
        hex_tx = data['hex_tx']
        if re.match(pattern, hex_tx) and len(hex_tx) % 2 == 0:
            tx_bytes = bytes.fromhex(hex_tx)
            tx = Transaction.create_from_struct(tx_bytes)

            data_to_sign = tx.get_sighash_all(clear_input_data=True)

            inputs = []
            for _input, address58 in self.manager.wallet.match_inputs(tx.inputs):
                if address58:
                    public_key_bytes, signature = self.manager.wallet.get_input_aux_data(
                        data_to_sign,
                        self.manager.wallet.get_private_key(address58)
                    )
                    input_data = base64.b64encode(P2PKH.create_input_data(public_key_bytes, signature)).decode('utf-8')
                    # TODO maybe this is a multisig address, not P2PKH
                    inputs.append({'tx_id': _input.tx_id.hex(), 'index': _input.index, 'data': input_data})

            ret = {'success': True, 'inputs': inputs}
        else:
            ret = {'success': False}
        return json.dumps(ret).encode('utf-8')

    def render_POST(self, request):
        """ Decode the nano contract transaction

        Post data should be a json with the following items:
        start_value: interval start value
        end_value: interval end value
        amount: token quantity user wants to stake in nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return 'Unable to decode JSON'.encode('utf-8')

        for param in PARAMS_POST:
            if param not in data:
                return get_missing_params_msg(param)

        if not data['start_value'] and not data['end_value']:
            return get_missing_params_msg('start_value or end_value')

        inputs_tx, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(data['amount'])
        inputs = []
        for _input in inputs_tx:
            inputs.append({'tx_id': _input.tx_id.hex(), 'index': _input.index})

        outputs = []
        if total_inputs_amount - data['amount'] > 0:
            addr = self.manager.wallet.get_unused_address(mark_as_used=True)
            outputs.append({'address': addr, 'amount': (total_inputs_amount - data['amount'])})

        address = self.manager.wallet.get_unused_address(mark_as_used=True)

        ret = {'address': address,
               'start_value': data['start_value'],
               'end_value': data['end_value'],
               'inputs': inputs,
               'outputs': outputs
               }
        return json.dumps(ret).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request, 'GET, POST, PUT, OPTIONS')
