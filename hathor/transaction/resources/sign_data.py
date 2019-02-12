import json

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.base_transaction import int_to_bytes
from hathor.transaction.scripts import create_output_script
from hathor.wallet.exceptions import InvalidAddress


@register_resource
class SignDataResource(resource.Resource):
    """ Implements a web server API to get sign data of a tx.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /sign_data/
            We expect 'outputs[]' and 'inputs[]' as request args
            'outputs[]': stringified json with an array of outputs
            'inputs[]': stringified json with an array of inputs
            We return success (bool) and the data_to_sign

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        outputs_to_decode = request.args[b'outputs[]']
        inputs_to_decode = request.args[b'inputs[]']

        outputs = []
        for output_to_decode in outputs_to_decode:
            output = json.loads(output_to_decode.decode('utf-8'))
            try:
                address = decode_address(output['address'])  # bytes
            except InvalidAddress:
                return json.dumps({
                    'success': False,
                    'message': 'The address {} is invalid'.format(output['address'])
                }, indent=4).encode('utf-8')

            value = int(output['value'])
            timelock_value = output.get('timelock')
            timelock = int_to_bytes(int(timelock_value), 4) if timelock_value else None
            outputs.append(TxOutput(value, create_output_script(address, timelock)))

        inputs = []
        for input_to_decode in inputs_to_decode:
            input_tx = json.loads(input_to_decode.decode('utf-8'))
            index = int(input_tx['index'])
            tx_id = bytes.fromhex(input_tx['tx_id'])
            inputs.append(TxInput(tx_id, index, b''))

        tx = Transaction(outputs=outputs, inputs=inputs)
        data_to_sign = tx.get_sighash_all()

        return json.dumps({'success': True, 'data_to_sign': data_to_sign.hex()}, indent=4).encode('utf-8')


SignDataResource.openapi = {
    '/sign_data': {
        'get': {
            'tags': ['transaction'],
            'operationId': 'sign_data',
            'summary': 'Transaction data to be signed',
            'description': 'Data to be signed is returned in hexadecimal',
            'parameters': [
                {
                    'name': 'inputs[]',
                    'in': 'query',
                    'description': 'Stringified array of inputs objects with tx_id and index',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'outputs[]',
                    'in': 'query',
                    'description': 'Stringified array of outputs objects with value, address and timelock',
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
                                        'data_to_sign': ('00010001000100000206b5e40d31270e5c074abe1440ca004518cb33348'
                                                         '57b771fe52660b6dfe9000000000007d000001976a914a3ac4c3e3a387b'
                                                         '2576a77bb504984f174489210688ac')
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
