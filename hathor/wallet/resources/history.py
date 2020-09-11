import math
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager


@register_resource
class HistoryResource(resource.Resource):
    """ Implements a web server API to return the history of tx of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
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

        history_tuple, total = self.manager.wallet.get_history(count, page)

        history = []
        for obj in history_tuple:
            history_dict = obj.to_dict()
            history_dict['tx_id'] = history_dict['tx_id']
            if 'from_tx_id' in history_dict:
                history_dict['from_tx_id'] = history_dict['from_tx_id']
            history.append(history_dict)

        data = {'history': history, 'total_pages': math.ceil(total / count)}
        return json_dumpb(data)


HistoryResource.openapi = {
    '/wallet/history': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_history',
            'summary': 'History of transactions of the wallet',
            'description': ('Returns a list with all the transactions of this'
                            ' wallet (in the page requested) and the total pages'),
            'parameters': [
                {
                    'name': 'page',
                    'in': 'query',
                    'description': 'Number of requested page',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'count',
                    'in': 'query',
                    'description': 'Quantity of elements in each page',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'history': [
                                            {
                                                'timestamp': 1547163030,
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
                                                'index': 0,
                                                'value': 1909,
                                                'address': '1EhoiVeWRDqzyabqNhsnSzhUvhBWNWvCsg',
                                                'voided': False
                                            },
                                            {
                                                'timestamp': 1547163030,
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
                                                'index': 1,
                                                'value': 55,
                                                'address': '1Dxu6qynYeX8CmipocnYPQy8X7TaHHCtrM',
                                                'voided': False
                                            }
                                        ],
                                        'total_pages': 7
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
