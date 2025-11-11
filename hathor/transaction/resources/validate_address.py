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

import base64
from typing import Union

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.manager import HathorManager
from hathor.transaction.scripts import create_base_script
from hathor.util import api_catch_exceptions, json_dumpb


@register_resource
class ValidateAddressResource(Resource):
    """ Implements a web server API that receives a string and returns whether it's a valid address and its script.

    The actual implementation is forwarded to _ValidateAddressResource, this only instantiates that class.

    You must run with option `--status <PORT>`.
    """

    def __init__(self, manager):
        super().__init__()
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def getChild(self, name, request):
        return _ValidateAddressResource(self.manager, name)


class _ValidateAddressResource(Resource):
    """ Actual implementation of ValidateAddressResource.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, address: Union[str, bytes]):
        super().__init__()
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        if isinstance(address, bytes):
            address = address.decode('ascii')
        assert isinstance(address, str)
        self.address = address

    @api_catch_exceptions
    def render_GET(self, request):
        """ Get request /validate_address/<address> that returns a script if address is valid.
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        try:
            base_script = create_base_script(self.address)
        except Exception as e:
            ret = {
                'valid': False,
                'error': type(e).__name__,
                'msg': str(e),
            }
        else:
            ret = {
                'valid': True,
                'script': base64.b64encode(base_script.get_script()).decode('ascii'),
                'address': base_script.get_address(),
                'type': base_script.get_type().lower(),
            }

        return json_dumpb(ret)


ValidateAddressResource.openapi = {
    '/validate_address/{address}': {
        'x-visibility': 'public',
        'x-path-params-regex': {
            'address': '.*',
        },
        'x-rate-limit': {
            'global': [
                {
                    'rate': '2000r/s',
                    'burst': 200,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '50r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['transaction'],
            'operationId': 'validate_address',
            'summary': 'Validate address and also create output script',
            'parameters': [
                {
                    'in': 'path',
                    'name': 'address',
                    'description': 'Base58 address to be decoded',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                }
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'schema': {
                                'type': 'object',
                                'properties': {
                                    'valid': {
                                        'type': 'boolean',
                                    },
                                    'script': {
                                        'type': 'string',  # base64 encoded
                                    },
                                    'address': {
                                        'type': 'string',  # base58 encoded
                                    },
                                    'type': {
                                        'type': 'string',
                                        'enum': [
                                            'p2pkh',
                                            'multisig',
                                        ],
                                    },
                                }
                            },
                            'examples': {
                                'valid_address': {
                                    'summary': 'Valid P2PKH address response',
                                    'value': {
                                        'valid': True,
                                        'script': 'dqkUr6YAVWv0Ps6bjgSGuqMb1GqCw6+IrA==',
                                        'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
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
