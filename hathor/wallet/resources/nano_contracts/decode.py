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

import re
import struct

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, set_cors
from hathor.transaction.scripts import NanoContractMatchValues
from hathor.transaction.vertex_parser import vertex_deserializer
from hathor.util import json_dumpb


@register_resource
class NanoContractDecodeResource(Resource):
    """ Implements a web server API that receives hex form of a tx and returns decoded value

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request):
        """ Get request /wallet/nano-contract/decode/ that returns the tx decoded, if success

        Expects 'hex_tx' as GET parameter

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        raw_args = get_args(request)
        if b'hex_tx' in raw_args:
            requested_decode = raw_args[b'hex_tx'][0].decode('utf-8')
        else:
            return get_missing_params_msg('hex_tx')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            try:
                tx = vertex_deserializer.deserialize(tx_bytes)
            except struct.error:
                data = {'success': False, 'message': 'Invalid transaction'}
                return json_dumpb(data)

            outputs = []
            nano_contract = None
            for _output in tx.outputs:
                _nano_contract = NanoContractMatchValues.parse_script(_output.script)
                if _nano_contract:
                    nano_contract = _nano_contract.to_human_readable()
                    nano_contract['value'] = _output.value
                    continue
                else:
                    outputs.append(_output.to_human_readable())

            my_inputs, other_inputs = self.manager.wallet.separate_inputs(tx.inputs, self.manager.tx_storage)

            my_inputs = [_in.to_human_readable() for _in in my_inputs]
            other_inputs = [_in.to_human_readable() for _in in other_inputs]

            data = {
                'success': True,
                'nano_contract': nano_contract,
                'outputs': outputs,
                'my_inputs': my_inputs,
                'other_inputs': other_inputs
            }
        else:
            data = {'success': False, 'message': 'Invalid transaction'}
        return json_dumpb(data)


NanoContractDecodeResource.openapi = {
    '/wallet/nano-contract/decode': {
        'x-visibility': 'private',
        'get': {
            'tags': ['nano-contract'],
            'operationId': 'nano_contract_decode',
            'summary': 'Decode nano contract',
            'description': 'Returns the nano contract transaction decoded',
            'parameters': [
                {
                    'name': 'hex_tx',
                    'in': 'query',
                    'description': 'Nano contract to be decoded in hexadecimal',
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
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'nano_contract': {
                                            'type': 'NanoContractMatchValues',
                                            'oracle_pubkey_hash': '6o6ul2c+sqAariBVW+CwNaSJb9w=',
                                            'min_timestamp': 1,
                                            'oracle_data_id': 'some_id',
                                            'value_dict': {
                                                '1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz': 300
                                            },
                                            'fallback_pubkey_hash': '13Y2oCMN8Lb6F3RLoPEofZz1bvX75dvEb',
                                            'value': 2000
                                        },
                                        'outputs': [
                                            {
                                                'type': 'P2PKH',
                                                'address': '1Q4qyTjhpUXUZXzwKs6Yvh2RNnF5J1XN9a',
                                                'timelock': None,
                                                'value': 4294967295,
                                                'token_data': 0
                                            }
                                        ],
                                        'my_inputs': [
                                            {
                                                'tx_id': ('7918fd6dfe9df2abf3010b1403efbeda'
                                                          'fcc86167a5c44cf65cd525ca40ca43b7'),
                                                'index': 0,
                                                'data': ''
                                            }
                                        ],
                                        'other_inputs': []
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid transaction',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid transaction'
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
