from twisted.web import resource
from hathor.api_util import set_cors

import json


class StateWalletResource(resource.Resource):
    """ Implements a web server API with GET return the state of the wallet
        State says if the wallet is locked or unlocked

        You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, wallet):
        self.wallet = wallet

    def render_GET(self, request):
        """ GET request for /wallet/state/
            Returns a boolean saying if the wallet is locked
            'is_locked': True|False

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'is_locked': self.wallet.is_locked(),
            'type': self.wallet.type.value
        }

        return json.dumps(data, indent=4).encode('utf-8')
