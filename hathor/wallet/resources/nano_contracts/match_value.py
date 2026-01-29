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
import binascii
import struct
from json import JSONDecodeError
from typing import Any, NamedTuple

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_missing_params_msg, render_options, set_cors
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.util import json_dumpb, json_loadb
from hathor.wallet.exceptions import InvalidAddress
from hathorlib.scripts import P2PKH, NanoContractMatchValues

PARAMS_POST = ['values', 'fallback_address', 'oracle_pubkey_hash', 'oracle_data_id', 'total_value', 'input_value']

PARAMS_PUT = ['hex_tx', 'new_values', 'input_value']


class DecodedPostParams(NamedTuple):
    value_dict: dict[bytes, int]
    fallback_address: bytes
    min_timestamp: int
    oracle_pubkey_hash: bytes
    total_value: int
    oracle_data_id: str
    input_value: int


class DecodedPutParams(NamedTuple):
    new_value_dict: dict[bytes, int]
    input_value: int
    tx_bytes: bytes


@register_resource
class NanoContractMatchValueResource(Resource):
    """ Implements a web server API to create/update MatchValue nano contract txs.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Creates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        values: list[{'address', 'value'}], with bet address and value
        fallback_address: if none of the addresses above is the winner, this address
                          can execute the contract
        oracle_pubkey_hash: oracle's public key hashed
        oracle_data_id: oracle's id about this nano contract
        total_value: nano contract total value
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        try:
            data = json_loadb(request.content.read())
        except JSONDecodeError:
            return json_dumpb({'success': False, 'message': 'Invalid format for post data'})

        for param in PARAMS_POST:
            if param not in data:
                return get_missing_params_msg(param)

        try:
            decoded_params = self.decode_post_params(data)
        except ValueError as e:
            return json_dumpb({'success': False, 'message': e.message})

        nano_contract = NanoContractMatchValues(
            decoded_params.oracle_pubkey_hash, decoded_params.min_timestamp, decoded_params.oracle_data_id,
            decoded_params.value_dict, decoded_params.fallback_address
        )

        tx_outputs = []
        tx_outputs.append(TxOutput(decoded_params.total_value, nano_contract.create_output_script()))

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(
            decoded_params.input_value,
            self.manager.tx_storage
        )
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, decoded_params.input_value)
        if change_tx:
            tx_outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))
        tx_inputs = [TxInput(txin.tx_id, txin.index, b'') for txin in inputs]

        tx = Transaction(inputs=tx_inputs, outputs=tx_outputs)

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json_dumpb(ret)

    def decode_post_params(self, data: dict[str, Any]) -> DecodedPostParams:
        """Decode the data required on POST request. Raise an error if any of the
        fields is not of the expected type.
        """
        value_dict = {}
        try:
            for item in data['values']:
                addr = decode_address(item['address'])
                value_dict[addr] = int(item['value'])
        except InvalidAddress:
            raise ValueError('Invalid \'address\' in parameters: {}'.format(item['address']))
        except ValueError:
            raise ValueError('Invalid \'value\' in parameters: {}'.format(item['value']))

        if data['fallback_address']:
            try:
                fallback_address = decode_address(data['fallback_address'])
            except InvalidAddress:
                raise ValueError('Invalid \'fallback_address\' in parameters')
        else:
            fallback_address = b'\x00'

        if data.get('min_timestamp'):
            try:
                min_timestamp = int(data['min_timestamp'])
            except ValueError:
                raise ValueError('Invalid \'min_timestamp\' in parameters')
        else:
            min_timestamp = int(self.manager.reactor.seconds())

        try:
            oracle_pubkey_hash = base64.b64decode(data['oracle_pubkey_hash'])
        except binascii.Error:
            raise ValueError('Invalid \'oracle_pubkey_hash\' in parameters')

        try:
            total_value = int(data['total_value'])
        except ValueError:
            raise ValueError('Invalid \'total_value\' in parameters')

        return DecodedPostParams(value_dict, fallback_address, min_timestamp, oracle_pubkey_hash, total_value,
                                 data['oracle_data_id'].encode('utf-8'), data['input_value'])

    def render_PUT(self, request):
        """ Updates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        hex_tx: tx being updated, in hex value
        new_values: list[{'address', 'value'}], with bet address and value
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'PUT')

        try:
            data = json_loadb(request.content.read())
        except JSONDecodeError:
            return json_dumpb({'success': False, 'message': 'Invalid format for post data'})

        for param in PARAMS_PUT:
            if param not in data:
                return get_missing_params_msg(param)

        try:
            decoded_params = self.decode_put_params(data)
        except ValueError as e:
            return json_dumpb({'success': False, 'message': e.message})

        try:
            tx = Transaction.create_from_struct(decoded_params.tx_bytes)
        except struct.error:
            return json_dumpb({'success': False, 'message': 'Could not decode hex transaction'})

        tx_outputs = []
        nano_contract = None
        for _output in tx.outputs:
            _nano_contract = NanoContractMatchValues.parse_script(_output.script)
            if _nano_contract:
                total_value = _output.value
                nano_contract = _nano_contract
            else:
                tx_outputs.append(_output)

        if not nano_contract:
            return json_dumpb({'success': False, 'message': 'Nano contract not found'})

        for address, value in decoded_params.new_value_dict.items():
            nano_contract.value_dict[address] = value

        tx.outputs = tx_outputs

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(
            decoded_params.input_value,
            self.manager.tx_storage
        )
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, decoded_params.input_value)
        if change_tx:
            tx.outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))

        tx.outputs.insert(0, TxOutput(total_value, nano_contract.create_output_script()))

        for txin in inputs:
            tx.inputs.append(TxInput(txin.tx_id, txin.index, b''))

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json_dumpb(ret)

    def decode_put_params(self, data: dict[str, Any]) -> DecodedPutParams:
        """Decode the data required on PUT request. Raise an error if any of the
        fields is not of the expected type.
        """
        value_dict = {}
        try:
            for item in data['new_values']:
                addr = decode_address(item['address'])
                value_dict[addr] = int(item['value'])
        except InvalidAddress:
            raise ValueError('Invalid \'address\' in parameters: {}'.format(item['address']))
        except ValueError:
            raise ValueError('Invalid \'value\' in parameters: {}'.format(item['value']))

        try:
            input_value = int(data['input_value'])
        except ValueError:
            raise ValueError('Invalid \'input_value\' in parameters')

        try:
            tx_bytes = bytes.fromhex(data['hex_tx'])
        except ValueError:
            raise ValueError('Could not decode hex transaction')

        return DecodedPutParams(value_dict, input_value, tx_bytes)

    def render_OPTIONS(self, request):
        return render_options(request, 'GET, POST, PUT, OPTIONS')


NanoContractMatchValueResource.openapi = {
    '/wallet/nano-contract/match-value': {
        'x-visibility': 'private',
        'post': {
            'tags': ['nano-contract'],
            'operationId': 'nano_contract_match_value_post',
            'summary': 'Create a match value nano contract',
            'description': 'Returns the hexadecimal of the created nano contract',
            'requestBody': {
                'description': 'Data to create the nano contract',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/NanoContractPOST'
                        },
                        'examples': {
                            'data': {
                                'summary': 'Data to create the nano contract',
                                'value': {
                                    'oracle_data_id': 'some_id',
                                    'total_value': 2000,
                                    'input_value': 2000,
                                    'min_timestamp': 1,
                                    'fallback_address': '1CBxvu6tFPTU8ygSPj9vyEadf9DsqTwy3D',
                                    'values': [
                                        {
                                            'address': '1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz',
                                            'value': 300
                                        }
                                    ],
                                    'oracle_pubkey_hash': '6o6ul2c+sqAariBVW+CwNaSJb9w='
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
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'hex_tx': ('00013ff00000000000005c3899fc0000000000000000000100010002005d9e609'
                                                   'fb85c512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd30002bb17'
                                                   '1de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c25d9e609fb'
                                                   '85c512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd300007b1007'
                                                   '736f6d655f6964045bfc631902012c473045022067aa6e62d123a96b817332e2c'
                                                   '40480af781799b5e2854be59ee82cb54823b054022100a4a4ccb96970bf0b39ef'
                                                   '8fa3b6a296e7f02e1fe2020f4bbe1f23321ded1aae27210309a5a288617b2f168'
                                                   '5a8dd0d4460bdb935cf72475f6bf10d2063cfdb86f70129000007d000001976a9'
                                                   '14f7934a91973cd100d753304f9a98267c8d4e6c0a88ac00000000')
                                    }
                                },
                                'error': {
                                    'summary': 'Parameter error',
                                    'value': {
                                        'success': False,
                                        'message': 'Parameter error message'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        'put': {
            'tags': ['nano-contract'],
            'operationId': 'nano_contract_match_value_put',
            'summary': 'Update a match value nano contract',
            'description': 'Returns the hexadecimal of the updated nano contract',
            'requestBody': {
                'description': 'Data to update the nano contract',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/NanoContractPUT'
                        },
                        'examples': {
                            'data': {
                                'summary': 'Data to update the nano contract',
                                'value': {
                                    'new_values': [
                                        {
                                            'address': '1CBxvu6tFPTU8ygSPj9vyEadf9DsqTwy3D',
                                            'value': 500
                                        }
                                    ],
                                    'input_value': 2000,
                                    'hex_tx': ('000100000000000000005c38a2bd00000000000000000001000200000075b16110c1b'
                                               'b244c6b8f23882c1846c1f6ec4e03427ecb676549381cecf11711000000000007d000'
                                               '006676a914ea8eae97673eb2a01aae20555be0b035a4896fdc88ba5007736f6d655f6'
                                               '964c0510400000001c15219007abc3b0c0425d3065c43f6bccdc16aa871f3bbad9ced'
                                               '28f002012c1900f7934a91973cd100d753304f9a98267c8d4e6c0a5554da250101d1d'
                                               '0ffffffff00001976a914fd05059b6006249543b82f36876a17c73fd2267b88ac0000'
                                               '0000')
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
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'success': True,
                                        'hex_tx': ('00013ff00000000000005c3899fc0000000000000000000100010002005d9e609'
                                                   'fb85c512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd30002bb17'
                                                   '1de3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c25d9e609fb'
                                                   '85c512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd300007b1007'
                                                   '736f6d655f6964045bfc631902012c473045022067aa6e62d123a96b817332e2c'
                                                   '40480af781799b5e2854be59ee82cb54823b054022100a4a4ccb96970bf0b39ef'
                                                   '8fa3b6a296e7f02e1fe2020f4bbe1f23321ded1aae27210309a5a288617b2f168'
                                                   '5a8dd0d4460bdb935cf72475f6bf10d2063cfdb86f70129000007d000001976a9'
                                                   '14f7934a91973cd100d753304f9a98267c8d4e6c0a88ac00000000')
                                    }
                                },
                                'error1': {
                                    'summary': 'Parameter error',
                                    'value': {
                                        'success': False,
                                        'message': 'Parameter error message'
                                    }
                                },
                                'error2': {
                                    'summary': 'Nano contract not found',
                                    'value': {
                                        'success': False,
                                        'message': 'Nano contract not found'
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
