import json

from twisted.web import resource

from hathor.api_util import set_cors


class BalanceResource(resource.Resource):
    """ Implements a web server API to return the balance of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/balance/
            Returns the int balance of the wallet

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {'balance': self.manager.wallet.balance._asdict()}
        return json.dumps(data, indent=4).encode('utf-8')
