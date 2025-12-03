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
from json import JSONDecodeError
from typing import Any, NamedTuple

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_missing_params_msg, render_options, set_cors
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, NanoContractMatchValues
from hathor.util import json_dumpb, json_loadb
from hathor.wallet.exceptions import InvalidAddress

PARAMS = ['spent_tx_id', 'spent_tx_index', 'oracle_data', 'oracle_signature', 'oracle_pubkey', 'address', 'value']


class DecodedParams(NamedTuple):
    spent_tx_id: bytes
    oracle_data: bytes
    oracle_signature: bytes
    oracle_pubkey: bytes
    address: bytes
    spent_tx_index: int
    value: int


@register_resource
class NanoContractExecuteResource(Resource):
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
            return json_dumpb({'success': False, 'message': 'No post data received'})

        try:
            data = json_loadb(content)
        except JSONDecodeError:
            return json_dumpb({'success': False, 'message': 'Invalid format for post data'})

        for param in PARAMS:
            if param not in data:
                return get_missing_params_msg(param)

        try:
            decoded_data = self.decode_params(data)
        except ValueError as e:
            return json_dumpb({'success': False, 'message': e.message})

        tx_outputs = []
        tx_outputs.append(TxOutput(decoded_data.value, P2PKH.create_output_script(decoded_data.address)))

        input_data = NanoContractMatchValues.create_input_data(
            decoded_data.oracle_data,
            decoded_data.oracle_signature,
            decoded_data.oracle_pubkey
        )
        tx_input = TxInput(decoded_data.spent_tx_id, decoded_data.spent_tx_index, input_data)
        tx = Transaction(inputs=[tx_input], outputs=tx_outputs)
        tx.storage = self.manager.tx_storage

        tx.parents = self.manager.get_new_tx_parents()
        tx.update_timestamp(int(self.manager.reactor.seconds()))
        tx.weight = self.manager.daa.minimum_tx_weight(tx)
        self.manager.cpu_mining_service.resolve(tx)
        success = self.manager.propagate_tx(tx)

        ret = {'success': success, 'hex_tx': tx.get_struct().hex()}
        return json_dumpb(ret)

    def render_OPTIONS(self, request):
        return render_options(request)

    def decode_params(self, data: dict[str, Any]) -> DecodedParams:
        """Decode the data required for execute operation. Raise an error if any of the
        fields is not of the expected type.
        """
        try:
            spent_tx_id = bytes.fromhex(data['spent_tx_id'])
        except ValueError:
            raise ValueError('Invalid \'spent_tx_id\' parameter')

        try:
            oracle_data = base64.b64decode(data['oracle_data'])
        except binascii.Error:
            raise ValueError('Invalid \'oracle_data\' parameter')

        try:
            oracle_signature = base64.b64decode(data['oracle_signature'])
        except binascii.Error:
            raise ValueError('Invalid \'oracle_signature\' parameter')

        try:
            oracle_pubkey = base64.b64decode(data['oracle_pubkey'])
        except binascii.Error:
            raise ValueError('Invalid \'oracle_pubkey\' parameter')

        try:
            address = decode_address(data['address'])
        except InvalidAddress:
            raise ValueError('Invalid \'address\' parameter')

        return DecodedParams(spent_tx_id, oracle_data, oracle_signature, oracle_pubkey,
                             address, data['spent_tx_index'], data['value'])


NanoContractExecuteResource.openapi = {
    '/wallet/nano-contract/execute': {
        'x-visibility': 'private',
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
