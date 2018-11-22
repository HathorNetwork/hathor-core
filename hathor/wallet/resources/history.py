from twisted.web import resource
from hathor.api_util import set_cors

import json
import math


class HistoryResource(resource.Resource):
    """ Implements a web server API to return the history of tx of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, wallet):
        self.wallet = wallet

    def render_GET(self, request):
        """ GET request for /wallet/history/
            Expects 'page' and 'count' as request args
            'page' is the pagination number
            'count' is the number of elements in each page

            Returns a history array (can be 'SpentTx' or 'UnspentTx') and the total number of pages

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        page = int(request.args[b'page'][0])
        count = int(request.args[b'count'][0])

        history_tuple, total = self.wallet.get_history(count, page)

        history = []
        for obj in history_tuple:
            history_dict = obj.to_dict()
            history_dict['tx_id'] = history_dict['tx_id']
            if 'from_tx_id' in history_dict:
                history_dict['from_tx_id'] = history_dict['from_tx_id']
            history.append(history_dict)

        data = {
            'history': history,
            'total_pages': math.ceil(total / count)
        }
        return json.dumps(data, indent=4).encode('utf-8')
