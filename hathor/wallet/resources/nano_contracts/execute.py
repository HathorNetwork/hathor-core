from twisted.web import resource

from hathor.api_util import set_cors, render_options, get_missing_params_msg
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import NanoContractMatchValues, P2PKH

import json
import base58
import base64

PARAMS = ['spent_tx_id', 'spent_tx_index', 'oracle_data', 'oracle_signature', 'oracle_pubkey', 'address', 'value']


class NanoContractExecuteResource(resource.Resource):
    """ Implements a web server API to execute a nano contract tx/

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Creates and propagates a tx to spend a nano contract output.

        Post data should be a json with the following items:
        spent_tx_id: tx id being spent
        spent_tx_index: tx index being spent
        oracle_data: the data provided by the oracle
        oracle_signature: signature of the oracle data
        oracle_pubkey: oracle's public key
        address: the winning address
        value: nano contract total value

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        content = request.content.read()
        if not content:
            return json.dumps({'success': False, 'message': 'No post data received'}).encode('utf-8')

        try:
            data = json.loads(content.decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS:
            if param not in data:
                return get_missing_params_msg(param)

        spent_tx_id = bytes.fromhex(data['spent_tx_id'])
        spent_tx_index = data['spent_tx_index']
        oracle_data = base64.b64decode(data['oracle_data'])
        oracle_signature = base64.b64decode(data['oracle_signature'])
        oracle_pubkey = base64.b64decode(data['oracle_pubkey'])
        address = base58.b58decode(data['address'])
        value = data['value']

        tx_outputs = []
        tx_outputs.append(TxOutput(value, P2PKH.create_output_script(address)))

        input_data = NanoContractMatchValues.create_input_data(oracle_data, oracle_signature, oracle_pubkey)
        tx_input = TxInput(spent_tx_id, spent_tx_index, input_data)
        tx = Transaction(inputs=[tx_input], outputs=tx_outputs)
        tx.storage = self.manager.tx_storage

        tx.parents = self.manager.get_new_tx_parents()
        tx.update_timestamp(int(self.manager.reactor.seconds()))
        tx.weight = self.manager.minimum_tx_weight(tx)
        tx.resolve()
        success = self.manager.propagate_tx(tx)

        ret = {'success': success, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)
