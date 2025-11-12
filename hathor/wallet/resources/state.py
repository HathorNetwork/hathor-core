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
from hathor.api_util import Resource, set_cors
from hathor.util import json_dumpb


@register_resource
class StateWalletResource(Resource):
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

        return json_dumpb(data)


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
