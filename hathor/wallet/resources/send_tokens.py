from twisted.web import resource, server
from hathor.api_util import set_cors

import json


class SendTokensResource(resource.Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, factory):
        # Important to have the factory so we can know the tx_storage
        self.factory = factory

    def render_POST(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data_bytes = request.args[b'data'][0]
        data = json.loads(data_bytes.decode('utf-8'))
        # TODO create tx
        print(data)

        ret = {
            'success': True
        }
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        set_cors(request, 'GET, POST, OPTIONS')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write('')
        request.finish()
        return server.NOT_DONE_YET
