import struct

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import get_missing_params_msg, parse_get_arguments, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.manager import HathorManager
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.resources.transaction import get_tx_extra_data
from hathor.util import json_dumpb

ARGS = ['hex_tx']


@register_resource
class DecodeTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and returns the object

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request: Request) -> bytes:
        """ Get request /decode_tx/ that returns the tx decoded, if success.

        Expects 'hex_tx' as GET parameter.
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        parsed = parse_get_arguments(request.args, ARGS)
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        try:
            tx_bytes = bytes.fromhex(parsed['args']['hex_tx'])
            tx = tx_or_block_from_bytes(tx_bytes)
            tx.storage = self.manager.tx_storage
            data = get_tx_extra_data(tx)
        except ValueError:
            data = {'success': False, 'message': 'Invalid hexadecimal data'}
        except struct.error:
            data = {'success': False, 'message': 'Could not decode transaction'}

        return json_dumpb(data)


DecodeTxResource.openapi = {
    '/decode_tx': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '200r/s',
                    'burst': 200,
                    'delay': 100
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
            'operationId': 'decode_tx',
            'summary': 'Decode transaction',
            'parameters': [
                {
                    'name': 'hex_tx',
                    'in': 'query',
                    'description': 'Transaction to be decoded in hexadecimal',
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
                                    'summary': 'Transaction decoded',
                                    'value': {
                                        'tx': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'nonce': 17076,
                                            'timestamp': 1539271482,
                                            'version': 1,
                                            'weight': 14.0,
                                            'parents': [],
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
                                            'outputs': [],
                                            'tokens': []
                                        },
                                        'meta': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'spent_outputs': [
                                                ['0', [
                                                    '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
                                                ]],
                                                ['1', [
                                                    '00002b3ce4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
                                                ]]
                                            ],
                                            'received_by': [],
                                            'children': [
                                                '00002b3ee4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22d'
                                            ],
                                            'conflict_with': [],
                                            'voided_by': [],
                                            'twins': [],
                                            'accumulated_weight': 10,
                                            'score': 12,
                                            'first_block': None
                                        },
                                        'spent_outputs': {
                                            0: '00002b3ce4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22e'
                                        },
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Error when decoding transaction',
                                    'value': {
                                        'success': False
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
