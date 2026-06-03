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
from hathor.api_util import APIVersion, Resource, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.manager import HathorManager
from hathor.util import json_dumpb


@register_resource
class BalanceResource(Resource):
    """ Implements a web server API to return the balance of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, api_version: APIVersion) -> None:
        super().__init__(api_version)
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/balance/
            Returns the int balance of the wallet

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if not self.manager.wallet:
            return {'success': False, 'message': 'No wallet started on node'}

        wallet_balance = self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID]
        data = {
            'success': True,
            'balance': {
                'available': self.api_version.unsigned_amount_to_response(wallet_balance.available),
                'locked': self.api_version.unsigned_amount_to_response(wallet_balance.locked),
            },
        }
        return json_dumpb(data)


BalanceResource.openapi = {
    '/wallet/balance': {
        'x-visibility': 'private',
        'x-api-versions': ['v1a', 'v2'],
        'x-api-version-overrides': {
            'v2': [
                {
                    'path': [
                        'get', 'responses', '200', 'content', 'application/json', 'examples', 'success', 'value',
                        'balance', 'available',
                    ],
                    'value': '1.000000000000000000',
                },
                {
                    'path': [
                        'get', 'responses', '200', 'content', 'application/json', 'examples', 'success', 'value',
                        'balance', 'locked',
                    ],
                    'value': '1.000000000000000000',
                },
            ],
        },
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
