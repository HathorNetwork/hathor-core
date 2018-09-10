from twisted.web import resource
from hathor.api_util import set_cors
from hathor.transaction import Transaction

import json


class DecodeTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and returns the object

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        tx_bytes = bytes.fromhex(request.args[b'hex_tx'][0].decode('utf-8'))

        data = {
            'transaction': Transaction.create_from_struct(tx_bytes).to_json()
        }
        return json.dumps(data, indent=4).encode('utf-8')