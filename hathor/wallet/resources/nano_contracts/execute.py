import base64
import json

import base58
from twisted.web import resource

from hathor.api_util import get_missing_params_msg, render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, NanoContractMatchValues

PARAMS = ['spent_tx_id', 'spent_tx_index', 'oracle_data', 'oracle_signature', 'oracle_pubkey', 'address', 'value']


@register_resource
class NanoContractExecuteResource(resource.Resource):
    """ Implements a web server API to execute a nano contract tx/

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        self.manager = manager

    def render_POST(self, request):
        """ Creates and propagates a tx to spend a nano contract output.

        Post data should be a json with the following items:
        spent_tx_id: tx id being spent
        spent_tx_index: tx index being spent
        oracle_data: the data provided by the oracle
        oracle_signature: signature of the oracle data
        oracle_pubkey: oracle's public key
        address: the winning address
        value: nano contract total value

        :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        content = request.content.read()
        if not content:
            return json.dumps({'success': False, 'message': 'No post data received'}).encode('utf-8')

        try:
            data = json.loads(content.decode('utf-8'))
        except json.JSONDecodeError:
            return json.dumps({'success': False, 'message': 'Invalid format for post data'}).encode('utf-8')

        for param in PARAMS:
            if param not in data:
                return get_missing_params_msg(param)

        spent_tx_id = bytes.fromhex(data['spent_tx_id'])
        spent_tx_index = data['spent_tx_index']
        oracle_data = base64.b64decode(data['oracle_data'])
        oracle_signature = base64.b64decode(data['oracle_signature'])
        oracle_pubkey = base64.b64decode(data['oracle_pubkey'])
        address = base58.b58decode(data['address'])
        value = data['value']

        tx_outputs = []
        tx_outputs.append(TxOutput(value, P2PKH.create_output_script(address)))

        input_data = NanoContractMatchValues.create_input_data(oracle_data, oracle_signature, oracle_pubkey)
        tx_input = TxInput(spent_tx_id, spent_tx_index, input_data)
        tx = Transaction(inputs=[tx_input], outputs=tx_outputs)
        tx.storage = self.manager.tx_storage

        tx.parents = self.manager.get_new_tx_parents()
        tx.update_timestamp(int(self.manager.reactor.seconds()))
        tx.weight = self.manager.minimum_tx_weight(tx)
        tx.resolve()
        success = self.manager.propagate_tx(tx)

        ret = {'success': success, 'hex_tx': tx.get_struct().hex()}
        return json.dumps(ret).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)


NanoContractExecuteResource.openapi = {
    '/wallet/nano-contract/execute': {
        'post': {
            'tags': ['nano-contract'],
            'operationId': 'nano_contract_execute',
            'summary': 'Execute nano contract',
            'description': 'Returns the hexadecimal of the propagated transaction',
            'requestBody': {
                'description': 'Data to execute nano contract',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/NanoContractExecute'
                        },
                        'examples': {
                            'data': {
                                'summary': 'Data to execute nano contract',
                                'value': {
                                    'spent_tx_id': '6da000cdbd93d71052a45d33809f9fbd4400f0ec614ed7fcec7e01071629946e',
                                    'spent_tx_index': 0,
                                    'oracle_data': 'B3NvbWVfaWQEW/xjGQIBLA==',
                                    'oracle_signature': ('MEUCIGeqbmLRI6lrgXMy4sQEgK94F5m14oVL5Z7oLLVII7BU'
                                                         'AiEApKTMuWlwvws574+jtqKW5/AuH+ICD0u+HyMyHe0aric='),
                                    'oracle_pubkey': 'Awmloohhey8WhajdDURgvbk1z3JHX2vxDSBjz9uG9wEp',
                                    'address': '1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz',
                                    'value': 2000
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
                                        'hex_tx': ('00013ff00000000000005c3899fc0000000000000000000100010002005d9e609f'
                                                   'b85c512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd30002bb171d'
                                                   'e3490828028ec5eef3325956acb6bcffa6a50466bb9a81d38363c25d9e609fb85c'
                                                   '512ac590221aed8cc5e7b7f646a4511e61ec401eba7bda794bd300007b1007736f'
                                                   '6d655f6964045bfc631902012c473045022067aa6e62d123a96b817332e2c40480'
                                                   'af781799b5e2854be59ee82cb54823b054022100a4a4ccb96970bf0b39ef8fa3b6'
                                                   'a296e7f02e1fe2020f4bbe1f23321ded1aae27210309a5a288617b2f1685a8dd0d'
                                                   '4460bdb935cf72475f6bf10d2063cfdb86f70129000007d000001976a914f7934a'
                                                   '91973cd100d753304f9a98267c8d4e6c0a88ac00000000')
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
                                    'summary': 'Propagation error',
                                    'value': {
                                        'success': False,
                                        'message': 'Propagation error message'
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
