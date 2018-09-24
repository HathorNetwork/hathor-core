from twisted.web import resource
from hathor.api_util import set_cors

import json


class AddressResource(resource.Resource):
    """ Implements a web server API to return an unused address of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/address/
            Expects a parameter 'new' (boolean) that says if we should create a new address
            Returns the address (new or old)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        new = request.args[b'new'][0].decode('utf-8') == 'true'

        if new:
            # When user clicks 'Generate new address' we have to mark the old one
            # as used and return a new one but not mark the new as used
            # Because if the user refreshs the page we need to show the same
            self.manager.wallet.get_unused_address(mark_as_used=True)

        address = self.manager.wallet.get_unused_address(mark_as_used=False)

        data = {
            'address': address,
        }
        return json.dumps(data, indent=4).encode('utf-8')
