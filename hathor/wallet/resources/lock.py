# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.util import json_dumpb


@register_resource
class LockWalletResource(Resource):
    """ Implements a web server API with POST to lock the wallet

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def render_POST(self, request):
        """ Lock the wallet

            :return: Boolean if the user locked the wallet with success
            :rtype: string (json) dict['success', bool]
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        self.manager.wallet.lock()

        ret = {'success': True}
        return json_dumpb(ret)

    def render_OPTIONS(self, request):
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
