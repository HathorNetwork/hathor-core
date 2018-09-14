from twisted.web import resource
from hathor.api_util import set_cors

import json
import math


class TransactionResource(resource.Resource):
    """ Implements a web server API to return the tx.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # XXX Check why all args are coming in bytes [pedro 2018-09-05]
        if b'id' in request.args:
            # Get one tx

            tx = self.manager.tx_storage.get_transaction_by_hash(request.args[b'id'][0].decode('utf-8'))
            data = tx.to_json(decode_script=True)
            data['raw'] = tx.get_struct().hex()
        else:
            # Get all tx
            page = int(request.args[b'page'][0])
            count = int(request.args[b'count'][0])

            transactions = self.manager.tx_storage.get_latest_tx_blocks(count=count, page=page)

            serialized_tx = [tx.to_json() for tx in transactions]

            data = {
                'transactions': serialized_tx,
                'total_pages': math.ceil(self.manager.tx_storage.get_count_tx_blocks() / count)
            }

        return json.dumps(data, indent=4).encode('utf-8')
