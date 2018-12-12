from twisted.web import resource
from hathor.api_util import set_cors, get_missing_params_msg
from hathor.transaction import Transaction

import json
import struct
import re


class SignTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and signs the inputs
    belonging to the user's wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request /decode_tx/ that returns the signed tx, if success

            Expects 'hex_tx' as GET parameter

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if b'hex_tx' in request.args:
            requested_decode = request.args[b'hex_tx'][0].decode('utf-8')
        else:
            return get_missing_params_msg('hex_tx')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            prepare_to_send = False
            if b'prepare_to_send' in request.args:
                _prepare_to_send = request.args[b'prepare_to_send'][0].decode('utf-8')
                prepare_to_send = _prepare_to_send == 'true'

            try:
                tx = Transaction.create_from_struct(tx_bytes)
                tx.storage = self.manager.tx_storage
                self.manager.wallet.sign_transaction(tx)

                if prepare_to_send:
                    tx.parents = self.manager.get_new_tx_parents()
                    tx.update_timestamp(int(self.manager.reactor.seconds()))
                    tx.weight = self.manager.minimum_tx_weight(tx)
                    tx.resolve()

                data = {
                    'hex_tx': tx.get_struct().hex(),
                    'success': True
                }
            except struct.error:
                data = {'success': False}

        else:
            data = {'success': False}
        return json.dumps(data).encode('utf-8')
