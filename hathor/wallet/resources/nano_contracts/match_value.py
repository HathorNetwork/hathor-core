import base64
import json

import base58
from twisted.web import resource

from hathor.api_util import get_missing_params_msg, render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, NanoContractMatchValues

PARAMS_POST = ['values', 'fallback_address', 'oracle_pubkey_hash', 'oracle_data_id', 'total_value', 'input_value']

PARAMS_PUT = ['hex_tx', 'new_values', 'input_value']


@register_resource
class NanoContractMatchValueResource(resource.Resource):
    """ Implements a web server API to create/update MatchValue nano contract txs.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Creates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        values: List[{'address', 'value'}], with bet address and value
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
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS_POST:
            if param not in data:
                return get_missing_params_msg(param)

        value_dict = {}
        for item in data['values']:
            value_dict[base58.b58decode(item['address'])] = item['value']

        fallback_address = base58.b58decode(data['fallback_address']) if data['fallback_address'] else b'\x00'
        min_timestamp = data['min_timestamp'] if data.get('min_timestamp') else int(self.manager.reactor.seconds())

        nano_contract = NanoContractMatchValues(
            base64.b64decode(data['oracle_pubkey_hash']), min_timestamp, data['oracle_data_id'].encode('utf-8'),
            value_dict, fallback_address)

        tx_outputs = []
        tx_outputs.append(TxOutput(data['total_value'], nano_contract.create_output_script()))

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(data['input_value'])
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, data['input_value'])
        if change_tx:
            tx_outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))
        tx_inputs = [TxInput(txin.tx_id, txin.index, b'') for txin in inputs]

        tx = Transaction(inputs=tx_inputs, outputs=tx_outputs)

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

    def render_PUT(self, request):
        """ Updates a nano contract tx and returns it in hexadecimal format.

        Post data should be a json with the following items:
        hex_tx: tx being updated, in hex value
        new_values: List[{'address', 'value'}], with bet address and value
        input_value: amount this wallet should stake in the nano contract

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'PUT')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS_PUT:
            if param not in data:
                return get_missing_params_msg(param)

        tx_bytes = bytes.fromhex(data['hex_tx'])
        tx = Transaction.create_from_struct(tx_bytes)

        new_value_dict = {}
        for item in data['new_values']:
            new_value_dict[base58.b58decode(item['address'])] = item['value']

        input_value = data['input_value']

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
            return json.dumps({'success': False, 'message': 'Nano contract not found'}).encode('utf-8')

        for address, value in new_value_dict.items():
            nano_contract.value_dict[address] = value

        tx.outputs = tx_outputs

        inputs, total_inputs_amount = self.manager.wallet.get_inputs_from_amount(input_value)
        change_tx = self.manager.wallet.handle_change_tx(total_inputs_amount, input_value)
        if change_tx:
            tx.outputs.append(TxOutput(change_tx.value, P2PKH.create_output_script(change_tx.address)))

        tx.outputs.insert(0, TxOutput(total_value, nano_contract.create_output_script()))

        [tx.inputs.append(TxInput(txin.tx_id, txin.index, b'')) for txin in inputs]

        ret = {'success': True, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

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
