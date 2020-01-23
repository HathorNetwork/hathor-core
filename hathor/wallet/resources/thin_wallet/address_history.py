import json
from typing import Set

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings

settings = HathorSettings()


@register_resource
class AddressHistoryResource(resource.Resource):
    """ Implements a web server API to return the address history

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /thin_wallet/address_history/
            Expects 'addresses[]' as request args
            'addresses[]' is an array of address

            Returns an array of WalletIndex for each address

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        wallet_index = self.manager.tx_storage.wallet_index

        if not wallet_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        addresses = request.args[b'addresses[]']

        # Pagination variables
        has_more = False
        first_hash = None
        first_address = None
        total_added = 0

        history = []
        seen: Set[bytes] = set()
        for idx, address_to_decode in enumerate(addresses):
            address = address_to_decode.decode('utf-8')
            hashes = wallet_index.get_sorted_from_address(address)
            start_index = 0
            if b'hash' in request.args and idx == 0:
                # It's not the first request, so we must continue from the hash
                # but we do it only for the first address

                # Find index where is the hash
                ref_hash = request.args[b'hash'][0].decode('utf-8')
                # TODO Validate if value is a valid hash
                try:
                    ref_hash_bytes = bytes.fromhex(ref_hash)
                    start_index = hashes.index(ref_hash_bytes)
                except ValueError:
                    # ref_hash is not in the list
                    return json.dumps({'success': False, 'message': 'Hash {} not found on address {}'.format(ref_hash, address_to_decode)}, indent=4).encode('utf-8')

            end_index = start_index + settings.MAX_TX_ADDRESSES_HISTORY - total_added
            to_iterate = hashes[start_index:end_index]
            for tx_hash in to_iterate:
                tx = self.manager.tx_storage.get_transaction(tx_hash)
                if tx_hash not in seen:
                    seen.add(tx_hash)
                    history.append(tx.to_json_extended())
                    total_added += 1

            if len(hashes) > end_index:
                # We stopped in the middle of the txs of this address
                has_more = True
                first_hash = hashes[end_index].hex()
                first_address = address_to_decode.decode('utf-8')
                break

        data = {
            'success': True,
            'history': history,
            'has_more': has_more,
            'first_hash': first_hash,
            'first_address': first_address
        }
        return json.dumps(data, indent=4).encode('utf-8')


AddressHistoryResource.openapi = {
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
            'summary': 'History of some addresses',
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
