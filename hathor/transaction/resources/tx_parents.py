from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager


@register_resource
class TxParentsResource(resource.Resource):
    """Return tx parents for new transactions

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /tx_parents/
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.can_start_mining():
            data = {
                'success': False,
                'message': 'Node syncing',
            }
        else:
            tx_parents = self.manager.get_new_tx_parents()
            data = {
                'success': True,
                'tx_parents': [x.hex() for x in tx_parents],
            }
        return json_dumpb(data)


TxParentsResource.openapi = {
    '/tx_parents': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '30r/s'
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['transaction'],
            'operationId': 'tx_parents',
            'summary': 'Return tx parents for new transactions',
            'parameters': [],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'tx_parents': [
                                            '000000001cd4fd3559222ebb40d39189e46ae3982d93f7be2f68652d0653a224',
                                            '00000000ce12d48152bd5e36a6a40bc9b501251bb7f1df2350c4c4ac34ad1f21',
                                        ],
                                    }
                                },
                                'error1': {
                                    'summary': 'Node syncing',
                                    'value': {
                                        'success': False,
                                        'message': 'Node syncing',
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}
