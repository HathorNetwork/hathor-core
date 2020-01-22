import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class StateWalletResource(resource.Resource):
    """ Implements a web server API with GET return the state of the wallet
        State says if the wallet is locked or unlocked

        You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/state/
            Returns a boolean saying if the wallet is locked
            'is_locked': True|False

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {'is_locked': self.manager.wallet.is_locked(), 'type': self.manager.wallet.type.value}

        return json.dumps(data, indent=4).encode('utf-8')


StateWalletResource.openapi = {
    '/wallet/state': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_state',
            'summary': 'State of the wallet',
            'description': 'Returns if the wallet is locked and its type',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'is_locked': False,
                                        'type': 'hd'
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
