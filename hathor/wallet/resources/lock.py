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

import json

from twisted.web import resource

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource


@register_resource
class LockWalletResource(resource.Resource):
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
            :rtype: string (json) Dict['success', bool]
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        self.manager.wallet.lock()

        ret = {'success': True}
        return json.dumps(ret, indent=4).encode('utf-8')

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
