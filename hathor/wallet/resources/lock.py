# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
