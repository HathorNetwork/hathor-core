from twisted.web import resource
from hathor.api_util import set_cors

import json


class BalanceResource(resource.Resource):
    """ Implements a web server API to return the balance of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, wallet):
        self.wallet = wallet

    def render_GET(self, request):
        """ GET request for /wallet/balance/
            Returns the int balance of the wallet

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {'balance': self.wallet.balance}
        return json.dumps(data, indent=4).encode('utf-8')
