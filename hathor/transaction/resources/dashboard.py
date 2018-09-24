from twisted.web import resource
from hathor.api_util import set_cors

import json


class DashboardTransactionResource(resource.Resource):
    """ Implements a web server API to return dashboard data for tx.
        Returns some blocks and some transactions (quantity comes from the frontend)

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /dashboard-tx/ that return a list of blocks and tx
            We expect two GET parameters: 'block' and 'tx'

            'block': int that indicates de quantity of blocks I should return
            'tx': int that indicates de quantity of tx I should return

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # Get quantity for each
        block_count = int(request.args[b'block'][0])
        tx_count = int(request.args[b'tx'][0])

        transactions = self.manager.tx_storage.get_latest_transactions(count=tx_count)
        serialized_tx = [tx.to_json() for tx in transactions]

        blocks = self.manager.tx_storage.get_latest_blocks(count=block_count)
        serialized_blocks = [block.to_json() for block in blocks]

        data = {
            'transactions': serialized_tx,
            'blocks': serialized_blocks,
        }

        return json.dumps(data, indent=4).encode('utf-8')
