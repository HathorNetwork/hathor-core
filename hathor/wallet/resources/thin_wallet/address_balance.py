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

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathor.util import json_dumpb
from hathor.wallet.exceptions import InvalidAddress
from hathorlib.scripts import parse_address_script

if TYPE_CHECKING:
    from hathor.transaction import TxOutput


class TokenData:
    received: int = 0
    spent: int = 0
    name: str = ''
    symbol: str = ''

    def to_dict(self):
        return {
            'received': self.received,
            'spent': self.spent,
            'name': self.name,
            'symbol': self.symbol,
        }


@register_resource
class AddressBalanceResource(Resource):
    """ Implements a web server API to return the address balance

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager

    def has_address(self, output: 'TxOutput', requested_address: str) -> bool:
        """ Check if output address is the same as requested_address
        """
        if output.is_token_authority():
            return False

        script_type_out = parse_address_script(output.script)
        if script_type_out:
            if script_type_out.address == requested_address:
                return True
        return False

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_balance/
            Expects 'address' as request args

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        addresses_index = self.manager.tx_storage.indexes.addresses
        tokens_index = self.manager.tx_storage.indexes.tokens

        if not addresses_index or not tokens_index:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        raw_args = get_args(request)
        if b'address' in raw_args:
            requested_address = raw_args[b'address'][0].decode('utf-8')
        else:
            return get_missing_params_msg('address')

        try:
            # Check if address is valid
            decode_address(requested_address)
        except InvalidAddress:
            return json_dumpb({
                'success': False,
                'message': 'Invalid \'address\' parameter'
            })

        tokens_data: dict[bytes, TokenData] = defaultdict(TokenData)
        tx_hashes = addresses_index.get_from_address(requested_address)
        for tx_hash in tx_hashes:
            tx = self.manager.tx_storage.get_transaction(tx_hash)
            meta = tx.get_metadata(force_reload=True)
            if not meta.voided_by:
                # We consider the spent/received values only if is not voided by
                for tx_input in tx.inputs:
                    tx2 = self.manager.tx_storage.get_transaction(tx_input.tx_id)
                    tx2_output = tx2.outputs[tx_input.index]
                    if self.has_address(tx2_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx2.get_token_uid(tx2_output.get_token_index())
                        tokens_data[token_uid].spent += tx2_output.value

                for tx_output in tx.outputs:
                    if self.has_address(tx_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx.get_token_uid(tx_output.get_token_index())
                        tokens_data[token_uid].received += tx_output.value

        return_tokens_data: dict[str, dict[str, Any]] = {}
        for token_uid in tokens_data.keys():
            if token_uid == self._settings.HATHOR_TOKEN_UID:
                tokens_data[token_uid].name = self._settings.HATHOR_TOKEN_NAME
                tokens_data[token_uid].symbol = self._settings.HATHOR_TOKEN_SYMBOL
            else:
                try:
                    token_info = tokens_index.get_token_info(token_uid)
                    tokens_data[token_uid].name = token_info.get_name()
                    tokens_data[token_uid].symbol = token_info.get_symbol()
                except KeyError:
                    # Should never get here because this token appears in our wallet index
                    # But better than get a 500 error
                    tokens_data[token_uid].name = '- (unable to fetch token information)'
                    tokens_data[token_uid].symbol = '- (unable to fetch token information)'
            return_tokens_data[token_uid.hex()] = tokens_data[token_uid].to_dict()

        data = {
            'success': True,
            'total_transactions': len(tx_hashes),
            'tokens_data': return_tokens_data
        }
        return json_dumpb(data)


AddressBalanceResource.openapi = {
    '/thin_wallet/address_balance': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s',
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
            'tags': ['wallet'],
            'operationId': 'address_balance',
            'summary': 'Balance of an address',
            'parameters': [
                {
                    'name': 'address',
                    'in': 'query',
                    'description': 'Address to get balance',
                    'required': True,
                    'schema': {
                        'type': 'string'
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
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'total_transactions': 5,
                                        'tokens_data': {
                                            '00': {
                                                'name': 'Hathor',
                                                'symbol': 'HTR',
                                                'received': 1000,
                                                'spent': 800,
                                            },
                                            '00000828d80dd4cd809c959139f7b4261df41152f4cce65a8777eb1c3a1f9702': {
                                                'name': 'NewCoin',
                                                'symbol': 'NCN',
                                                'received': 100,
                                                'spent': 20,
                                            },
                                        }
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid address',
                                    'value': {
                                        'success': False,
                                        'message': 'The address xx is invalid',
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
