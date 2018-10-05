from twisted.web import resource, server
from hathor.api_util import set_cors
from hathor.wallet.base_wallet import WalletOutputInfo, WalletInputInfo
from hathor.wallet.exceptions import InsuficientFunds, PrivateKeyNotFound, InputDuplicated, InvalidAddress
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
        """ POST request for /wallet/send_tokens/
            We expect 'data' as request args
            'data': stringified json with an array of inputs and array of outputs
            If inputs array is empty we use 'prepare_transaction_compute_inputs', that calculate the inputs
            We return success (bool)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data_bytes = request.args[b'data'][0]
        data = json.loads(data_bytes.decode('utf-8'))

        outputs = []
        for output in data['outputs']:
            try:
                address = self.manager.wallet.decode_address(output['address'])  # bytes
            except InvalidAddress:
                return self.return_POST(False, 'The address {} is invalid'.format(output['address']))

            value = int(output['value'])
            outputs.append(WalletOutputInfo(address=address, value=value))

        if len(data['inputs']) == 0:
            try:
                tx = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
            except InsuficientFunds:
                return self.return_POST(False, 'Insufficient funds')
        else:
            inputs = []
            for input_tx in data['inputs']:
                input_tx['private_key'] = None
                input_tx['index'] = int(input_tx['index'])
                input_tx['tx_id'] = bytes.fromhex(input_tx['tx_id'])
                inputs.append(WalletInputInfo(**input_tx))
            try:
                tx = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs)
            except (PrivateKeyNotFound, InputDuplicated):
                return self.return_POST(False, 'Invalid input to create transaction')

        # TODO Send tx to be mined
        tx.timestamp = int(self.manager.reactor.seconds())
        tx.weight = 10
        tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
        tx.storage = self.manager.tx_storage
        tx.resolve()

        success, message = tx.validate_tx_error()

        if success:
            self.manager.propagate_tx(tx)

        return self.return_POST(success, message)

    def return_POST(self, success, message):
        """ Auxiliar method to return result of POST method

            :param success: If tx was created successfully
            :type success: bool

            :param message: Message in case of error
            :type success: string

            :rtype: string (json)
        """
        ret = {
            'success': success,
            'message': message,
        }
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        set_cors(request, 'GET, POST, OPTIONS')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write('')
        request.finish()
        return server.NOT_DONE_YET
