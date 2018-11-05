from twisted.web import resource
from hathor.api_util import set_cors

import json


class TipsHistogramResource(resource.Resource):
    """ Implements a web server API to return the tips in a timestamp interval.
        Returns a list of timestamps and numbers of tips.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request to /tips-histogram/ that return the number of tips between two timestamp
            We expect two GET parameters: 'begin' and 'end'

            'begin': int that indicates the beginning of the interval
            'end': int that indicates the end of the interval

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # Get quantity for each
        begin = int(request.args[b'begin'][0])
        end = int(request.args[b'end'][0])

        v = []
        for timestamp in range(begin, end + 1):
            tx_tips = self.manager.tx_storage.get_tx_tips(timestamp)
            v.append((timestamp, len(tx_tips)))

        return json.dumps(v).encode('utf-8')
