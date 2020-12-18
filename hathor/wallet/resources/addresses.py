import json

from twisted.web import resource

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class AddressesResource(resource.Resource):
    """ Implements a web server API to return an unused address of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/addresses/

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.wallet or self.manager.wallet.type != self.manager.wallet.WalletType.HD:
            # We have this method only for HD wallet
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        addresses = self.manager.wallet.get_all_addresses()

        data = {
            'addresses': addresses,
        }
        return json.dumps(data, indent=4).encode('utf-8')


AddressesResource.openapi = {
    '/wallet/addresses': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_addresses',
            'summary': 'Addresses',
            'description': 'Returns all shared addresses from the wallet',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'addresses': ['15VZc2jy1L3LGFweZeKVbWMsTzfKFJLpsN']
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