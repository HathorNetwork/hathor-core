import json
from collections import defaultdict

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.transaction.scripts import parse_address_script

settings = HathorSettings()


@register_resource
class AddressBalanceResource(resource.Resource):
    """ Implements a web server API to return the address balance

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def should_add_output(self, output, requested_address):
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

        wallet_index = self.manager.tx_storage.wallet_index
        tokens_index = self.manager.tx_storage.tokens_index

        if not wallet_index or not tokens_index:
            request.setResponseCode(503)
            return json.dumps({'success': False}, indent=4).encode('utf-8')

        if b'address' in request.args:
            requested_address = request.args[b'address'][0].decode('utf-8')
        else:
            return get_missing_params_msg('address')

        amounts_by_token = defaultdict(int)
        tx_hashes = wallet_index.get_from_address(requested_address)
        for tx_hash in tx_hashes:
            tx = self.manager.tx_storage.get_transaction(tx_hash)
            meta = tx.get_metadata(force_reload=True)
            if not meta.voided_by:
                # We consider the spent/received values only if is not voided by
                for tx_input in tx.inputs:
                    tx2 = self.manager.tx_storage.get_transaction(tx_input.tx_id)
                    tx2_output = tx2.outputs[tx_input.index]
                    if self.should_add_value(tx2_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx2.get_token_uid(tx2_output.get_token_index())
                        token_uid_hex = token_uid.hex()
                        amounts_by_token[token_uid_hex]['spent'] += tx2_output.value

                for tx_output in tx.outputs:
                    if self.should_add_value(tx_output, requested_address):
                        # We just consider the address that was requested
                        token_uid = tx.get_token_uid(tx_output.get_token_index())
                        token_uid_hex = token_uid.hex()
                        amounts_by_token[token_uid_hex]['received'] += tx_output.value

        tokens_data = {}
        for token_uid_hex in amounts_by_token.keys():
            token_uid = bytes.fromhex(token_uid_hex)
            try:
                token_info = tokens_index.get_token_info(token_uid)
                tokens_data[token_uid_hex] = {'name': token_info.name, 'symbol': token_info.symbol}
            except KeyError:
                # Should never get here because this token appears in our wallet index
                # But better than get a 500 error
                return {'success': False, 'message': 'Unknown token'}

        data = {
            'success': True,
            'quantity': len(tx_hashes),
            'amounts_by_token': amounts_by_token,
            'tokens_data': tokens_data
        }
        return json.dumps(data, indent=4).encode('utf-8')


AddressBalanceResource.openapi = {
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
