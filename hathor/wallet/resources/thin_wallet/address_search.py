import json
from typing import Set

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings

settings = HathorSettings()


@register_resource
class AddressSearchResource(resource.Resource):
    """ Implements a web server API to return a paginated list of transactions address

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_search/
            Expects 'address' and 'count' as required request args
            'hash' and 'page' are optional args to be used in pagination

            'address' is a base58 address string
            'count' is an integer indicating the quantity of elements to be returned
            'hash' is the first address of the pagination to start the history
            'page' is either 'previous' or 'next' to indicate the page clicked

            Returns an array of WalletIndex until the count limit and the hash
            parameter for the next request, if has more
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        wallet_index = self.manager.tx_storage.wallet_index

        if not wallet_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        if b'address' not in request.args:
            return get_missing_params_msg('address')

        if b'count' not in request.args:
            return get_missing_params_msg('count')

        address = request.args[b'address'][0].decode('utf-8')
        try:
            count = min(int(request.args[b'count'][0]), settings.MAX_TX_COUNT)
        except ValueError:
            return json.dumps({
                'success': False,
                'message': 'Invalid \'count\' parameter, expected an int'
            }).encode('utf-8')

        hashes = wallet_index.get_from_address(address)
        # XXX To do a timestamp sorting, so the pagination works better
        # we must get all transactions and sort them
        # This is not optimal for performance
        transactions = [self.manager.tx_storage.get_transaction(tx_hash).to_json_extended() for tx_hash in hashes]
        sorted_transactions = sorted(transactions, key=lambda tx: tx['timestamp'], reverse=True)
        if b'hash' in request.args:
            # It's a paginated request, so 'page' must also be in request.args
            if b'page' not in request.args:
                return get_missing_params_msg('page')

            page = request.args[b'page'][0].decode('utf-8')
            if page != 'previous' and page != 'next':
                # Invalid value for page parameter
                return json.dumps({
                    'success': False,
                    'message': 'Invalid value for \'page\' parameter',
                }, indent=4).encode('utf-8')

            ref_hash = request.args[b'hash'][0].decode('utf-8')
            # Index where the reference hash is
            for ref_index, tx in enumerate(sorted_transactions):
                if tx['tx_id'] == ref_hash:
                    break
            else:
                # ref_hash is not in the list
                return json.dumps({
                    'success': False,
                    'message': 'Invalid hash {}'.format(ref_hash)
                }, indent=4).encode('utf-8')

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
        }
        return json.dumps(data, indent=4).encode('utf-8')


AddressSearchResource.openapi = {
    '/thin_wallet/address_history': {
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
            'operationId': 'address_history',
            'summary': 'History of some addresses. Important note: different requests (even pagination requests) '
                       'may return the same transaction for different addresses. We just validate if a transactions '
                       'was already added in the same request.',
            'parameters': [
                {
                    'name': 'addresses[]',
                    'in': 'query',
                    'description': 'Stringified array of addresses',
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
                                        'has_more': True,
                                        'first_hash': '00000299670db5814f69cede8b347f83'
                                                      '0f73985eaa4cd1ce87c9a7c793771332',
                                        'first_address': '1Pz5s5WVL52MK4EwBy9XVQUzWjF2LWWKiS',
                                        'history': [
                                            {
                                                "hash": "00000299670db5814f69cede8b347f83"
                                                        "0f73985eaa4cd1ce87c9a7c793771336",
                                                "timestamp": 1552422415,
                                                "is_voided": False,
                                                'parents': [
                                                    '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb5',
                                                    '00001417652b9d7bd53eb14267834eab08f27e5cbfaca45a24370e79e0348bb1'
                                                ],
                                                "inputs": [
                                                    {
                                                        "value": 42500000044,
                                                        "script": "dqkURJPA8tDMJHU8tqv3SiO18ZCLEPaIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "17Fbx9ouRUD1sd32bp4ptGkmgNzg7p2Krj",
                                                            "timelock": None
                                                            },
                                                        "token": "00",
                                                        "tx": "000002d28696f94f89d639022ae81a1d"
                                                              "870d55d189c27b7161d9cb214ad1c90c",
                                                        "index": 0
                                                        }
                                                    ],
                                                "outputs": [
                                                    {
                                                        "value": 42499999255,
                                                        "script": "dqkU/B6Jbf5OnslsQrvHXQ4WKDTSEGKIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "1Pz5s5WVL52MK4EwBy9XVQUzWjF2LWWKiS",
                                                            "timelock": None
                                                            },
                                                        "token": "00"
                                                        },
                                                    {
                                                        "value": 789,
                                                        "script": "dqkUrWoWhiP+qPeI/qwfwb5fgnmtd4CIrA==",
                                                        "decoded": {
                                                            "type": "P2PKH",
                                                            "address": "1GovzJvbzLw6x4H2a1hHb529cpEWzh3YRd",
                                                            "timelock": None
                                                            },
                                                        "token": "00"
                                                        }
                                                    ]
                                                }
                                        ]
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