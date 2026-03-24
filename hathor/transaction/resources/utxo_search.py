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

from typing import TYPE_CHECKING

from hathor._openapi.register import register_resource
from hathor.api_util import (
    Resource,
    get_arg_default,
    get_args,
    get_missing_params_msg,
    parse_args,
    parse_int,
    set_cors,
)
from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathor.util import json_dumpb
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class UtxoSearchResource(Resource):
    """ Implements a web server API to return a list of UTXOs that fit a given search criteria.

    You must run with option `--status <PORT>` and `--utxo-index`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        # Important to have the manager so we can know the tx_storage
        self._settings = get_global_settings()
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        """ Get request /utxo_search/ that returns available UTXOs for the specified criteria

            'token_uid': hex, the UID of the token to be considered ('00' for HTR)
            'address': string, the address from the script of the outputs
            'target_amount': int, the results will aim to be enough to complete this amount
            'target_timestamp': int, optional, what timestamp to consider for timelocked outputs
            'target_height': int, optional, what height to consider for rewards (which are always heightlocked)

            :rtype: string (json)
        """

        # setup
        tx_storage = self.manager.tx_storage
        if tx_storage.indexes.utxo is None:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        utxo_index = tx_storage.indexes.utxo
        height_index = tx_storage.indexes.height

        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        # parse required parameters
        raw_args = get_args(request)
        parsed = parse_args(raw_args, ['token_uid', 'address', 'target_amount'])
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        args = parsed['args']

        # token_uid parameter must be a valid hash
        try:
            token_uid = bytes.fromhex(args['token_uid'])
            if token_uid != self._settings.HATHOR_TOKEN_UID and len(token_uid) != 32:
                raise ValueError('not a valid hash length')
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'token_uid\': {e}'
            })

        # target amount parameter must be an integer
        try:
            target_amount = parse_int(args['target_amount'])
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'target_amount\': {e}'
            })

        # address parameter must be a valid address
        try:
            address = args['address']
            # XXX: calling decode address just so it raises an error if it fails
            decode_address(address)
        except InvalidAddress as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'address\': {e}'
            })

        # check the current best block to have a target_timestamp and target_height
        best_block_height, best_block_hash = height_index.get_height_tip()
        best_block = tx_storage.get_transaction(best_block_hash)

        target_timestamp = get_arg_default(raw_args, 'target_timestamp', best_block.timestamp)
        target_height = get_arg_default(raw_args, 'target_height', best_block_height)

        # collect UTXOs
        iter_utxos = utxo_index.iter_utxos(token_uid=token_uid, address=address, target_amount=target_amount,
                                           target_timestamp=target_timestamp, target_height=target_height)

        utxo_list = [{
            'txid': utxo.tx_id.hex(),
            'index': utxo.index,
            'amount': utxo.amount,
            'timelock': utxo.timelock,
            'heightlock': utxo.heightlock,
        } for utxo in iter_utxos]

        data = {'success': True, 'utxos': utxo_list}
        return json_dumpb(data)


UtxoSearchResource.openapi = {
    '/utxo_search': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '10r/s',
                    'burst': 100,
                    'delay': 50
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['utxo'],
            'operationId': 'utxo_search',
            'summary': 'Search UTXOs with given address/token/amount',
            'description': (
              'For a given token-uid, address and target-amount, get a list of UTXOs that are candidates to be inputs '
              'for a total of target-value. The resulsts will try to include the first UTXO with value higher or '
              'equal value as target-amount. No more than 256 entries will ever be returned by this API.'
             ),
            'parameters': [
                {
                    'name': 'token_uid',
                    'in': 'query',
                    'description': 'The UID of the token formatted as a HEX string, use "00" for HTR',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'target_amount',
                    'in': 'query',
                    'description': 'The target amount that the UTXOs should sum-up to, 1 means 0.01 HTR',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'address',
                    'in': 'query',
                    'description': 'The address that all UTXOs have',
                    'required': True,
                    'schema': {
                        'type': 'str'
                    }
                },
                {
                    'name': 'target_timestamp',
                    'in': 'query',
                    'description': (
                        'What timestamp to consider for timelocked outputs, by default uses the timestamp '
                        'from the current best block'
                    ),
                    'required': False,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'target_height',
                    'in': 'query',
                    'description': (
                        'What timestamp to consider for reward outputs (which are heightlocked), by default uses the '
                        'height from the current best block'
                    ),
                    'required': False,
                    'schema': {
                        'type': 'int'
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
                                    'summary': 'Success UTXO search',
                                    'value': {
                                        'success': True,
                                        'utxos': [
                                            {
                                                'txid': (
                                                    '339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792'
                                                ),
                                                'index': 0,
                                                'amount': 1_000_000_000,
                                                'timelock': None,
                                                'heightlock': 10,
                                            },
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid parameter',
                                    'value': {
                                        'success': False,
                                        'message': 'Failed to parse \'address\': foobar'
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
