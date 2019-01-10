import json
from threading import Lock
from typing import Optional

from twisted.internet import threads
from twisted.web import resource

from hathor.api_util import render_options, set_cors
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InputDuplicated, InsuficientFunds, InvalidAddress, PrivateKeyNotFound
from tests.resources.base_resource import TestDummyRequest


class SendTokensResource(resource.Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.lock = Lock()

    def _render_POST_thread(self, request: TestDummyRequest) -> bytes:
        """ POST request for /wallet/send_tokens/
            We expect 'data' as request args
            'data': stringified json with an array of inputs and array of outputs
            If inputs array is empty we use 'prepare_transaction_compute_inputs', that calculate the inputs
            We return success (bool)

            :rtype: string (json)
        """
        with self.lock:
            request.setHeader(b'content-type', b'application/json; charset=utf-8')
            set_cors(request, 'POST')

            post_data = json.loads(request.content.read().decode('utf-8'))
            data = post_data['data']

            outputs = []
            for output in data['outputs']:
                try:
                    address = self.manager.wallet.decode_address(output['address'])  # bytes
                except InvalidAddress:
                    return self.return_POST(False, 'The address {} is invalid'.format(output['address']))

                value = int(output['value'])
                timelock = output.get('timelock')
                outputs.append(WalletOutputInfo(address=address, value=value, timelock=timelock))

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

            tx.storage = self.manager.tx_storage
            # TODO Send tx to be mined

            max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
            tx.timestamp = max(max_ts_spent_tx + 1, int(self.manager.reactor.seconds()))
            tx.parents = self.manager.get_new_tx_parents(tx.timestamp)

            # Calculating weight
            weight = data.get('weight')
            if weight is None:
                weight = self.manager.minimum_tx_weight(tx)
            tx.weight = weight

        # There is no need to synchonize this slow part.
        tx.resolve()

        # Then, we synchonize again.
        with self.lock:
            success, message = tx.validate_tx_error()
            if success:
                success = self.manager.propagate_tx(tx)

        return self.return_POST(success, message, tx=tx)

    def render_POST(self, request):
        deferred = threads.deferToThread(self._render_POST_thread, request)
        deferred.addCallback(self._cb_tx_resolve, request)
        deferred.addErrback(self._err_tx_resolve, request)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _cb_tx_resolve(self, result, request):
        """ Called when `_render_POST_thread` finishes
        """
        request.write(result)
        request.finish()

    def _err_tx_resolve(self, reason, request):
        """ Called when an error occur in `_render_POST_thread`
        """
        request.processingFailed(reason)

    def return_POST(self, success: bool, message: str, tx: Optional[Transaction] = None) -> bytes:
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
        if tx:
            ret['tx'] = tx.to_json()
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)
