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

from math import log2
from typing import Any

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, set_cors, validate_tx_hash
from hathor.manager import HathorManager
from hathor.util import json_dumpb
from hathor.utils.weight import weight_to_work, work_to_weight

N_CONFIRMATION_BLOCKS: int = 6


@register_resource
class TransactionAccWeightResource(Resource):
    """ Implements a web server API to return the confirmation data of a tx

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def _render_GET_data(self, requested_hash: str) -> dict[str, Any]:
        success, message = validate_tx_hash(requested_hash, self.manager.tx_storage)
        if not success:
            return {'success': False, 'message': message}

        hash_bytes = bytes.fromhex(requested_hash)
        tx = self.manager.tx_storage.get_transaction(hash_bytes)

        if tx.is_block:
            return {'success': False, 'message': 'not allowed on blocks'}

        meta = tx.get_metadata()
        data: dict[str, Any] = {'success': True}

        if meta.first_block:
            block = self.manager.tx_storage.get_transaction(meta.first_block)
            stop_value = block.weight + log2(N_CONFIRMATION_BLOCKS)
            meta = tx.update_accumulated_weight(stop_value=weight_to_work(stop_value))
            acc_weight = work_to_weight(meta.accumulated_weight)
            acc_weight_raw = str(meta.accumulated_weight)
            data['accumulated_weight'] = acc_weight
            data['accumulated_weight_raw'] = acc_weight_raw
            data['accumulated_bigger'] = acc_weight > stop_value
            data['stop_value'] = stop_value
            data['confirmation_level'] = min(acc_weight / stop_value, 1)
        else:
            meta = tx.update_accumulated_weight()
            acc_weight = work_to_weight(meta.accumulated_weight)
            acc_weight_raw = str(meta.accumulated_weight)
            data['accumulated_weight'] = acc_weight
            data['accumulated_weight_raw'] = acc_weight_raw
            data['accumulated_bigger'] = False
            data['confirmation_level'] = 0
        return data

    def render_GET(self, request):
        """ Get request /transaction_acc_weight/ that returns the acc_weight data of a tx

            Expects 'id' (hash) as GET parameter of the tx we will return the data

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        raw_args = get_args(request)
        if b'id' not in raw_args:
            return get_missing_params_msg('id')

        requested_hash = raw_args[b'id'][0].decode('utf-8')
        data = self._render_GET_data(requested_hash)

        return json_dumpb(data)


TransactionAccWeightResource.openapi = {
    '/transaction_acc_weight': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '10r/s',
                    'burst': 20,
                    'delay': 10
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
            'tags': ['transaction'],
            'operationId': 'transaction_acc_weight',
            'summary': 'Accumulated weight data of a transaction',
            'description': 'Returns the accumulated weight and confirmation level of a transaction',
            'parameters': [
                {
                    'name': 'id',
                    'in': 'query',
                    'description': 'Hash in hex of the transaction/block',
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
                                        'accumulated_weight': 15.4,
                                        'accumulated_weight_raw': '43238',
                                        'confirmation_level': 0.88,
                                        'stop_value': 14.5,
                                        'accumulated_bigger': True,
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Transaction not found',
                                    'value': {
                                        'success': False,
                                        'message': 'Transaction not found'
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
