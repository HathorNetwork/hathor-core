from twisted.web import resource
from hathor.api_util import set_cors

import json


class HistoryResource(resource.Resource):
    """ Implements a web server API to return the history of tx of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, factory):
        # Important to have the factory so we can know the tx_storage
        self.factory = factory

    def render_GET(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'history': [
                {
                    'tx_id': '1234',
                    'index': 1,
                    'value': 1000,
                    'timestamp': 1536173681
                },
                {
                    'tx_id': '2345',
                    'index': 0,
                    'value': 5001,
                    'timestamp': 1536173659,
                },
                {
                    'tx_id': '7890',
                    'index': 0,
                    'value': 1001,
                    'timestamp': 1536173259,
                    'spent': '1111',
                },
            ]
        }
        return json.dumps(data, indent=4).encode('utf-8')
