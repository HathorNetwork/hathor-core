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

from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, parse_int, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathorlib.scripts import parse_address_script
from hathor.util import json_dumpb
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


@register_resource
class AddressSearchResource(Resource):
    """ Implements a web server API to return a paginated list of transactions address

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self._settings = get_global_settings()
        self.manager = manager

    def has_token_and_address(self, tx: 'BaseTransaction', address: str, token: bytes) -> bool:
        """ Validate if transaction has any input or output with the
            address and token sent as parameter
        """
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            spent_output = spent_tx.outputs[tx_input.index]

            input_token_uid = spent_tx.get_token_uid(spent_output.get_token_index())

            script_type_out = parse_address_script(spent_output.script)
            if script_type_out:
                if script_type_out.address == address and input_token_uid == token:
                    return True

        for tx_output in tx.outputs:
            output_token_uid = tx.get_token_uid(tx_output.get_token_index())

            script_type_out = parse_address_script(tx_output.script)
            if script_type_out:
                if script_type_out.address == address and output_token_uid == token:
                    return True

        return False

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_search/
            Expects 'address' and 'count' as required request args
            'token' is an optional parameter to define if the search wants an specific token only
            'hash' and 'page' are optional args to be used in pagination

            'address' is a base58 address string
            'count' is an integer indicating the quantity of elements to be returned
            'token' is the token uid in hex to be searched
            'hash' is the first address of the pagination to start the history
            'page' is either 'previous' or 'next' to indicate the page clicked

            Returns an array of WalletIndex until the count limit and the hash
            parameter for the next request, if has more
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        addresses_index = self.manager.tx_storage.indexes.addresses

        if not addresses_index:
            request.setResponseCode(503)
            return json_dumpb({'success': False})

        raw_args = get_args(request)
        if b'address' not in raw_args:
            return get_missing_params_msg('address')

        if b'count' not in raw_args:
            return get_missing_params_msg('count')

        try:
            address = raw_args[b'address'][0].decode('utf-8')
            # Check if address is valid
            decode_address(address)
        except InvalidAddress:
            return json_dumpb({
                'success': False,
                'message': 'Invalid \'address\' parameter'
            })

        try:
            count = parse_int(raw_args[b'count'][0], cap=self._settings.MAX_TX_COUNT)
        except ValueError as e:
            return json_dumpb({
                'success': False,
                'message': f'Failed to parse \'count\': {e}'
            })

        token_uid_bytes = None
        if b'token' in raw_args:
            # It's an optional parameter, we just check if it's a valid hex
            token_uid = raw_args[b'token'][0].decode('utf-8')

            try:
                token_uid_bytes = bytes.fromhex(token_uid)
            except ValueError as e:
                return json_dumpb({
                    'success': False,
                    'message': f'Failed to parse \'token\': {e}'
                })

        hashes = addresses_index.get_from_address(address)
        # XXX To do a timestamp sorting, so the pagination works better
        # we must get all transactions and sort them
        # This is not optimal for performance
        transactions = []
        for tx_hash in hashes:
            tx = self.manager.tx_storage.get_transaction(tx_hash)
            if token_uid_bytes and not self.has_token_and_address(tx, address, token_uid_bytes):
                # Request wants to filter by token but tx does not have this token
                # so we don't add it to the transactions array
                continue
            transactions.append(tx.to_json_extended())

        sorted_transactions = sorted(transactions, key=lambda tx: tx['timestamp'], reverse=True)
        if b'hash' in raw_args:
            # It's a paginated request, so 'page' must also be in raw_args
            if b'page' not in raw_args:
                return get_missing_params_msg('page')

            page = raw_args[b'page'][0].decode('utf-8')
            if page != 'previous' and page != 'next':
                # Invalid value for page parameter
                return json_dumpb({
                    'success': False,
                    'message': 'Invalid value for \'page\' parameter',
                })

            ref_hash = raw_args[b'hash'][0].decode('utf-8')
            # Index where the reference hash is
            for ref_index, tx in enumerate(sorted_transactions):
                if tx['tx_id'] == ref_hash:
                    break
            else:
                # ref_hash is not in the list
                return json_dumpb({
                    'success': False,
                    'message': 'Invalid hash {}'.format(ref_hash)
                })

            if page == 'next':
                # User clicked on 'Next' button, so the ref_hash is the last hash of the list
                # So I need to get the transactions after the ref
                start_index = ref_index + 1
                end_index = start_index + count
                ret_transactions = sorted_transactions[start_index:end_index]
                # If has more transactions after this
                has_more = len(sorted_transactions) > end_index
            else:
                # User clicked on 'Previous' button, so the ref_hash is the first hash of the list
                # So I need to get the transactions before the ref
                end_index = ref_index
                start_index = max(end_index - count, 0)
                ret_transactions = sorted_transactions[start_index:end_index]
                # If has more transactions before this
                has_more = start_index > 0
        else:
            ret_transactions = sorted_transactions[:count]
            has_more = len(sorted_transactions) > count

        data = {
            'success': True,
            'transactions': ret_transactions,
            'has_more': has_more,
            'total': len(sorted_transactions),
        }
        return json_dumpb(data)


AddressSearchResource.openapi = {
    '/thin_wallet/address_search': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '50r/s',
                    'burst': 50,
                    'delay': 30
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
            'operationId': 'address_search',
            'summary': 'Search history transactions of an address with pagination',
            'parameters': [
                {
                    'name': 'address',
                    'in': 'query',
                    'description': 'Address to be searched',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'count',
                    'in': 'query',
                    'description': 'Quantity of elements to return',
                    'required': True,
                    'schema': {
                        'type': 'int'
                    }
                },
                {
                    'name': 'page',
                    'in': 'query',
                    'description': 'If the user clicked "previous" or "next" button',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'hash',
                    'in': 'query',
                    'description': 'Hash reference for the pagination',
                    'required': False,
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
                                        'transactions': [
                                            {
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
                                                'timestamp': 1547163030,
                                                'version': 1,
                                                'weight': 18.861583646228,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb4',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb9'
                                                ],
                                                'inputs': [
                                                    {
                                                        'tx_id': ('0000088c5a4dfcef7fd3c04a5b1eccfd'
                                                                  '2de032b23749deff871b0a090000f5f6'),
                                                        'index': 1,
                                                        'data': ('RzBFAiEAvv17vp8XyHYq36PFlOGd7V2vzIkf+XIuqfyUnc2fZugC'
                                                                 'IDnwM7PdkA/qwt2QXLB3WnegtdOqV8gv+H63voWVbsScIQPqg7y2'
                                                                 'RanTdnQcDvFneIzjrUzJoPzkmoNStoN8XtLTUA==')
                                                    },
                                                    {
                                                        'tx_id': ('0000003398322f99355f37439e32881c'
                                                                  '83ff08b83e744e799b1d6a67f73bee45'),
                                                        'index': 0,
                                                        'data': ('RzBFAiEAqPvD18Uzd6NsMVkGMaI9RsxWqLow22W1KBHUUW/35UEC'
                                                                 'IEUU9pxJEHBvXyEwYAB2/bCiWxNd4iLvyvQXGKaSaDV2IQPDL3iZ'
                                                                 'vsDS8jdFDmlcvc2Em/ZNYYDOBWd3oZWxpuA5DQ==')
                                                    }
                                                ],
                                                'outputs': [
                                                    {
                                                        'value': 1909,
                                                        'script': 'dqkUllFFDJByV5TjVUly3Zc3bB4mMH2IrA=='
                                                    },
                                                    {
                                                        'value': 55,
                                                        'script': 'dqkUjjPg+zwG6JDe901I0ybQxcAPrAuIrA=='
                                                    }
                                                ],
                                                'tokens': [],
                                                'height': 12345,
                                            },
                                            {
                                                'tx_id': ('00000b8792cb13e8adb51cc7d866541f'
                                                          'c29b532e8dec95ae4661cf3da4d42cb4'),
                                                'timestamp': 1547163025,
                                                'version': 1,
                                                'weight': 17.995048894541107,
                                                'parents': [
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb9',
                                                    '0000088c5a4dfcef7fd3c04a5b1eccfd2de032b23749deff871b0a090000f5f6'
                                                ],
                                                'inputs': [
                                                    {
                                                        'tx_id': ('0000088c5a4dfcef7fd3c04a5b1eccfd'
                                                                  '2de032b23749deff871b0a090000f5f6'),
                                                        'index': 0,
                                                        'data': ('SDBGAiEA/rtsn1oQ68uGeTj/7IVtqijxoUxzr9S/u3UGAC7wQvU'
                                                                 'CIQDaYkL1R8LICfSCpYIn4xx6A+lxU0Fw3oKR1hK91fRnSiEDCo'
                                                                 'A74tfBQa4IR7iXtlz+jH9UV7+YthKX4yQNaMSMfb0=')
                                                    }
                                                ],
                                                'outputs': [
                                                    {
                                                        'value': 1894,
                                                        'script': 'dqkUduvtU77hZm++Pwavtl9OrOSA+XiIrA=='
                                                    },
                                                    {
                                                        'value': 84,
                                                        'script': 'dqkUjjPg+zwG6JDe901I0ybQxcAPrAuIrA=='
                                                    }
                                                ],
                                                'tokens': []
                                            }
                                        ],
                                        'has_more': True,
                                        'total': 10
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
