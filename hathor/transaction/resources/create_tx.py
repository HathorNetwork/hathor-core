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

import base64

from hathor.api_util import Resource, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.crypto.util import decode_address
from hathor.daa import minimum_tx_weight
from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import create_output_script
from hathor.util import api_catch_exceptions, json_dumpb, json_loadb


def from_raw_output(raw_output: dict, tokens: list[bytes]) -> TxOutput:
    value = raw_output['value']
    token_uid = raw_output.get('token_uid')
    if token_uid is not None:
        if token_uid not in tokens:
            tokens.append(token_uid)
        token_data = tokens.index(token_uid) + 1
    else:
        token_data = 0
    raw_script = raw_output.get('script')
    if raw_script:
        script = base64.b64decode(raw_script)
    else:
        address = decode_address(raw_output['address'])
        script = create_output_script(address)
    return TxOutput(value, script, token_data)


@register_resource
class CreateTxResource(Resource):
    """ Implements a web server API that receives inputs and outputs, and returns an unsigned tx (both data and hex).

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    @api_catch_exceptions
    def render_POST(self, request):
        """ Post request /create_tx/ that returns an encoded tx, if valid

            Expects {"inputs":[{"tx_id": <hex encoded>, "index": <int>, "data": <optional base64 encoded>}],
                     "outputs":[{"value": <int, 1.00 HTR = 100>, "token_uid": <optional omit for HTR, hex encoded>,
                     "address" or "script"}]} as POST data
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        body_content = json_loadb(request.content.read())

        raw_inputs = body_content.get('inputs', [])
        raw_outputs = body_content.get('outputs', [])

        inputs = [TxInput.create_from_dict(i) for i in raw_inputs]
        tokens = []
        outputs = [from_raw_output(i, tokens) for i in raw_outputs]

        timestamp = int(max(self.manager.tx_storage.latest_timestamp, self.manager.reactor.seconds()))
        parents = self.manager.get_new_tx_parents(timestamp)
        # this tx will have to be mined by tx-mining-server or equivalent
        tx = Transaction(
            timestamp=timestamp,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
            storage=self.manager.tx_storage,
        )
        fake_signed_tx = tx.clone()
        for tx_input in fake_signed_tx.inputs:
            # conservative estimate of the input data size to estimate a valid weight
            tx_input.data = b'\0' * 107
        tx.weight = minimum_tx_weight(fake_signed_tx)
        self.manager.verification_service.verifiers.tx.verify_unsigned_skip_pow(tx)

        if tx.is_double_spending():
            raise InvalidNewTransaction('At least one of your inputs has already been spent.')

        hex_data = bytes(tx).hex()
        data = tx.to_json()
        data.pop('hash', None)
        data.pop('nonce', None)

        return json_dumpb({
            'success': True,
            'hex_data': hex_data,
            'data': data,
        })


CreateTxResource.openapi = {
    '/create_tx': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '2000r/s',
                    'burst': 200,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '50r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'post': {
            'tags': ['transaction'],
            'operationId': 'create_tx',
            'summary': 'Create unsigned unmined raw transaction',
            'requestBody': {
                'description': 'Inputs and outputs to use',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'inputs': {
                                    'type': 'array',
                                    'items': {
                                        '$ref': '#/components/schemas/TxInput'
                                    }
                                },
                                'outputs': {
                                    'type': 'array',
                                    'items': {
                                        'oneOf': [
                                            {
                                                '$ref': '#/components/schemas/AddressOutput'
                                            },
                                            {
                                                '$ref': '#/components/schemas/ScriptOutput'
                                            },
                                        ]
                                    }
                                }
                            }
                        },
                        'examples': {
                            'tx': {
                                'summary': 'Example tx creation',
                                'value': {
                                    'inputs': [
                                        {
                                            'tx_id': '000005551d7740fd7d3c0acc50b5677f'
                                                     'dd844f1225985aa431e1712af2a2fd89',
                                            'index': 1,
                                        },
                                    ],
                                    'outputs': [
                                        {
                                            'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
                                            'value': 5600,
                                        },
                                    ],
                                }
                            }
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'schema': {
                                'success': {
                                    'type': 'boolean',
                                },
                                'hex_data': {
                                    'type': 'string',  # hex encoded serialized transaction
                                },
                                'data': {
                                    'type': 'object',
                                    'properties': {
                                        'timestamp': {
                                            'type': 'integer',
                                        },
                                        'version': {
                                            'type': 'integer',
                                        },
                                        'weight': {
                                            'type': 'number',
                                        },
                                        'parents': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string',  # hex encoded tx id
                                            }
                                        },
                                        'inputs': {
                                            'type': 'array',
                                            'items': {
                                                '$ref': '#/components/schemas/TxInput'
                                            }
                                        },
                                        'outputs': {
                                            'type': 'array',
                                            'items': {
                                                '$ref': '#/components/schemas/TxOutput'
                                            }
                                        },
                                        'tokens': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string',  # hex encoded token_uid
                                            }
                                        }
                                    }
                                }
                            },
                            'examples': {
                                'tx': {
                                    'summary': 'This is what could be returned from the example request.',
                                    'value': {
                                        'success': True,
                                        'hex_data': '0001000101000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e171'
                                                    '2af2a2fd89010000000015e000001976a914afa600556bf43ece9b8e0486baa3'
                                                    '1bd46a82c3af88ac40310c373eed982e5f63d94d0200000000b0e8be665f308f'
                                                    '1d48d2201060846203280062b1cccc4e3d657486e90000000071c0d2cafa192b'
                                                    '421bb5727c84174c999f9400d3be74331e7feba08a00000000',
                                        'data': {
                                            'timestamp': 1600379213,
                                            'version': 1,
                                            'weight': 17.047717984205683,
                                            'parents': [
                                                '00000000b0e8be665f308f1d48d2201060846203280062b1cccc4e3d657486e9',
                                                '0000000071c0d2cafa192b421bb5727c84174c999f9400d3be74331e7feba08a',
                                            ],
                                            'inputs': [
                                                {
                                                    'tx_id': '000005551d7740fd7d3c0acc50b5677f'
                                                             'dd844f1225985aa431e1712af2a2fd89',
                                                    'index': 1,
                                                    'data': '',
                                                },
                                            ],
                                            'outputs': [
                                                {
                                                    'value': 5600,
                                                    'token_data': 0,
                                                    'script': 'dqkUr6YAVWv0Ps6bjgSGuqMb1GqCw6+IrA==',
                                                },
                                            ],
                                            'tokens': []
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
}
