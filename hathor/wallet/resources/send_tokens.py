from twisted.web import resource, server
from hathor.api_util import set_cors
from hathor.wallet.wallet import WalletOutputInfo, WalletInputInfo
from hathor.transaction import Transaction

import json


class SendTokensResource(resource.Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_POST(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data_bytes = request.args[b'data'][0]
        data = json.loads(data_bytes.decode('utf-8'))

        # TODO Handling errors
        # Outputs or inputs invalids
        # Getting errors from methods and handling them
        outputs = []
        for output in data['outputs']:
            output['value'] = int(output['value'])
            outputs.append(WalletOutputInfo(**output))

        if len(data['inputs']) == 0:
            tx = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
        else:
            inputs = []
            for input_tx in data['inputs']:
                input_tx['private_key'] = None
                input_tx['index'] = int(input_tx['index'])
                input_tx['tx_id'] = bytes.fromhex(input_tx['tx_id'])
                inputs.append(WalletInputInfo(**input_tx))
            tx = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)

        # TODO Send tx to be mined
        print(tx)

        ret = {
            'success': True
        }
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        set_cors(request, 'GET, POST, OPTIONS')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write('')
        request.finish()
        return server.NOT_DONE_YET
