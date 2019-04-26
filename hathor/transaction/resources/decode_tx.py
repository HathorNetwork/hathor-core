import json
import re
import struct

from twisted.web import resource

from hathor.api_util import get_missing_params_msg, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.transaction import Transaction
from hathor.transaction.resources.transaction import get_tx_extra_data


@register_resource
class DecodeTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and returns the object

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
        """ Get request /decode_tx/ that returns the tx decoded, if success

            Expects 'hex_tx' as GET parameter

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        if b'hex_tx' in request.args:
            requested_decode = request.args[b'hex_tx'][0].decode('utf-8')
        else:
            return get_missing_params_msg('hex_tx')

        pattern = r'[a-fA-F\d]+'
        if re.match(pattern, requested_decode) and len(requested_decode) % 2 == 0:
            tx_bytes = bytes.fromhex(requested_decode)

            try:
                tx = Transaction.create_from_struct(tx_bytes)
                tx.storage = self.manager.tx_storage
                data = get_tx_extra_data(tx)
            except struct.error:
                data = {'success': False}

        else:
            data = {'success': False}
        return json.dumps(data, indent=4).encode('utf-8')


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
