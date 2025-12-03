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
from hathor.api_util import Resource, get_args, set_cors
from hathor.util import json_dumpb


@register_resource
class AddressResource(Resource):
    """ Implements a web server API to return an unused address of the wallet.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ GET request for /wallet/address/
            Expects a parameter 'new' (boolean) that says if we should create a new address
            Returns the address (new or old)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        raw_args = get_args(request)
        if b'new' in raw_args:
            new = raw_args[b'new'][0].decode('utf-8') == 'true'
        else:
            new = False

        if new:
            # When user clicks 'Generate new address' we have to mark the old one
            # as used and return a new one but not mark the new as used
            # Because if the user refreshs the page we need to show the same
            self.manager.wallet.get_unused_address(mark_as_used=True)

        address = self.manager.wallet.get_unused_address(mark_as_used=False)

        data = {
            'address': address,
        }
        return json_dumpb(data)


AddressResource.openapi = {
    '/wallet/address': {
        'x-visibility': 'private',
        'get': {
            'tags': ['private_wallet'],
            'operationId': 'wallet_address',
            'summary': 'Address',
            'description': 'Returns an address to be used in the wallet',
            'parameters': [
                {
                    'name': 'new',
                    'in': 'query',
                    'description': 'New or old address',
                    'required': True,
                    'schema': {
                        'type': 'boolean'
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'address': '15VZc2jy1L3LGFweZeKVbWMsTzfKFJLpsN'
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
