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

from typing import TYPE_CHECKING, Any

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.util import json_dumpb
from hathor.utils.api import ErrorResponse, QueryParams

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class BlockAtHeightResource(Resource):
    """ Implements a web server API to return the block at specific height.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        """ Get request /block_at_height/ that returns a block at height in parameter

            'height': int, the height of block to get

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        params = BlockAtHeightParams.from_request(request)
        if isinstance(params, ErrorResponse):
            return params.json_dumpb()

        # Get hash of the block with the height
        block_hash = self.manager.tx_storage.indexes.height.get(params.height)

        # If there is no block in the index with this height, block_hash will be None
        if block_hash is None:
            return json_dumpb({
                'success': False,
                'message': 'No block with height {}.'.format(params.height)
            })

        block = self.manager.tx_storage.get_block(block_hash)
        data = {'success': True, 'block': block.to_json_extended()}

        if params.include_transactions is None:
            pass

        elif params.include_transactions == 'txid':
            tx_ids: list[str] = []
            for tx in block.iter_transactions_in_this_block():
                tx_ids.append(tx.hash.hex())
            data['tx_ids'] = tx_ids

        elif params.include_transactions == 'full':
            tx_list: list[Any] = []
            for tx in block.iter_transactions_in_this_block():
                tx_list.append(tx.to_json_extended())
            data['transactions'] = tx_list

        else:
            return json_dumpb({
                'success': False,
                'message': 'Invalid include_transactions. Choices are: txid or full.'
            })

        return json_dumpb(data)


class BlockAtHeightParams(QueryParams):
    height: int
    include_transactions: str | None


BlockAtHeightResource.openapi = {
    '/block_at_height': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 100,
                    'delay': 50
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['block'],
            'operationId': 'block',
            'summary': 'Get block at height',
            'description': 'Returns the block at specific height in the best chain.',
            'parameters': [
                {
                    'name': 'height',
                    'in': 'query',
                    'description': 'Height of the block to get',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'include_transactions',
                    'in': 'query',
                    'description': 'Add transactions confirmed by this block.',
                    'required': False,
                    'schema': {
                        'type': 'string',
                        'enum': [
                            'txid',
                            'full',
                        ],
                    }
                },
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success block height 1',
                                    'value': {
                                        'success': True,
                                        'block': {
                                            'tx_id': ('080c8086376ab7105d17df1127a68ede'
                                                      'df54029a21b5d98841448cc23b5123ff'),
                                            'version': 0,
                                            'weight': 1.0,
                                            'timestamp': 1616094323,
                                            'is_voided': False,
                                            'inputs': [],
                                            'outputs': [
                                                {
                                                    'value': 6400,
                                                    'token_data': 0,
                                                    'script': 'dqkU4yipgEZjbphR/M3gUGjsbyb1s76IrA==',
                                                    'decoded': {
                                                        'type': 'P2PKH',
                                                        'address': 'HTEEV9FJeqBCYLUvkEHsWAAi6UGs9yxJKj',
                                                        'timelock': None
                                                    },
                                                    'token': '00',
                                                    'spent_by': None
                                                }
                                            ],
                                            'parents': [
                                                '339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792',
                                                '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952',
                                                '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'
                                            ],
                                            'height': 1
                                        }
                                    }
                                },
                                'error': {
                                    'summary': 'Block not found',
                                    'value': {
                                        'success': False,
                                        'message': 'Does not have a block with height 100.'
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}
