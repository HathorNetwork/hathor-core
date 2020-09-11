from math import log
from typing import TYPE_CHECKING

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, set_cors, validate_tx_hash
from hathor.cli.openapi_files.register import register_resource
from hathor.util import JsonDict, json_dumpb

if TYPE_CHECKING:
    from hathor.manager import HathorManager


@register_resource
class TransactionAccWeightResource(resource.Resource):
    """ Implements a web server API to return the confirmation data of a tx

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def _render_GET_data(self, requested_hash):
        success, message = validate_tx_hash(requested_hash, self.manager.tx_storage)
        if not success:
            return {'success': False, 'message': message}

        hash_bytes = bytes.fromhex(requested_hash)
        tx = self.manager.tx_storage.get_transaction(hash_bytes)

        if tx.is_block:
            return {'success': False, 'message': 'not allowed on blocks'}

        meta = tx.get_metadata()
        data: JsonDict = {'success': True}

        if meta.first_block:
            block = self.manager.tx_storage.get_transaction(meta.first_block)
            stop_value = block.weight + log(6, 2)
            meta = tx.update_accumulated_weight(stop_value=stop_value)
            data['accumulated_weight'] = meta.accumulated_weight
            data['accumulated_bigger'] = meta.accumulated_weight > stop_value
            data['stop_value'] = stop_value
            data['confirmation_level'] = min(meta.accumulated_weight / stop_value, 1)
        else:
            meta = tx.update_accumulated_weight()
            data['accumulated_weight'] = meta.accumulated_weight
            data['accumulated_bigger'] = False
            data['confirmation_level'] = 0
        return data

    def render_GET(self, request: Request) -> bytes:
        """ Get request /transaction_acc_weight/ that returns the acc_weight data of a tx

            Expects 'id' (hash) as GET parameter of the tx we will return the data

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if b'id' not in request.args:
            return get_missing_params_msg('id')

        requested_hash = request.args[b'id'][0].decode('utf-8')
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
