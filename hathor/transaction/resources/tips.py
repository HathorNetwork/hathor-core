import json

from twisted.web import resource

from hathor.api_util import set_cors


class TipsResource(resource.Resource):
    """ Implements a web server API to return the tips
        Returns a list of tips hashes

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /tips/ that return a list of tips hashes

            'timestamp' is an optional expected parameter to be used in the get_tx_tips method

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        timestamp = None
        if b'timestamp' in request.args:
            timestamp = int(request.args[b'timestamp'][0])

        tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
        ret = [tip.data.hex() for tip in tx_tips]
        return json.dumps(ret).encode('utf-8')
