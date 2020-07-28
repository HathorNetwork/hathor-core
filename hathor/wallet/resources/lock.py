from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.util import json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager


@register_resource
class LockWalletResource(resource.Resource):
    """ Implements a web server API with POST to lock the wallet

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def render_POST(self, request: Request) -> bytes:
        """ Lock the wallet

        Returns boolean if the user locked the wallet with success.
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        self.manager.wallet.lock()

        ret = {'success': True}
        return json_dumpb(ret)

    def render_OPTIONS(self, request: Request) -> int:
        return render_options(request)


LockWalletResource.openapi = {
    '/wallet/lock': {
        'x-visibility': 'private',
        'post': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_lock',
            'summary': 'Lock a wallet',
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Wallet locked',
                                    'value': {
                                        'success': True
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
