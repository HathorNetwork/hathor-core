import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings

settings = HathorSettings()


@register_resource
class BalanceResource(resource.Resource):
    """ Implements a web server API to return the balance of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/balance/
            Returns the int balance of the wallet

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {'balance': self.manager.wallet.balance[settings.HATHOR_TOKEN_UID]._asdict()}
        return json.dumps(data, indent=4).encode('utf-8')


BalanceResource.openapi = {
    '/wallet/balance': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_address',
            'summary': 'Balance',
            'description': 'Returns the current balance of the wallet (available and locked tokens)',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'balance': {
                                            'available': 5000,
                                            'locked': 1000
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
}
