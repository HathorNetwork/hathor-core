from twisted.web import resource
from hathor.api_util import set_cors

import json
import uuid


class AddressResource(resource.Resource):
    """ Implements a web server API to return a new address of the wallet.

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
            'address': str(uuid.uuid4())
        }
        return json.dumps(data, indent=4).encode('utf-8')
