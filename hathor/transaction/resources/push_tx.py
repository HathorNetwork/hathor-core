import struct
from typing import Any, Dict, cast

from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import parse_get_arguments, render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.exceptions import TxValidationError
from hathor.util import json_dumpb, json_loadb

ARGS = ['hex_tx']


@register_resource
class PushTxResource(resource.Resource):
    """ Implements a web server API that receives hex form of a tx and send it to the network

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def handle_push_tx(self, params: Dict[str, Any]) -> bytes:
        try:
            tx_bytes = bytes.fromhex(params['hex_tx'])
            tx = tx_or_block_from_bytes(tx_bytes)
        except ValueError:
            data = {'success': False, 'message': 'Invalid hexadecimal data', 'can_force': False}
        except struct.error:
            data = {
                'success': False,
                'message': 'This transaction is invalid. Try to decode it first to validate it.',
                'can_force': False
            }
        else:
            if tx.is_block:
                # It's a block and we can't push blocks
                data = {
                    'success': False,
                    'message': 'This transaction is invalid. A transaction must have at least one input',
                    'can_force': False
                }
            else:
                tx.storage = self.manager.tx_storage
                # If this tx is a double spending, don't even try to propagate in the network
                assert isinstance(tx, Transaction)
                is_double_spending = tx.is_double_spending()
                if is_double_spending:
                    data = {
                        'success': False,
                        'message': 'Invalid transaction. At least one of your inputs has already been spent.',
                        'can_force': False
                    }
                else:
                    success, message = tx.validate_tx_error()

                    if success or params['force']:
                        message = ''
                        try:
                            success = self.manager.propagate_tx(tx, fails_silently=False)
                        except (InvalidNewTransaction, TxValidationError) as e:
                            success = False
                            message = str(e)
                        data = {'success': success, 'message': message}
                        if success:
                            data['tx'] = tx.to_json()
                    else:
                        data = {'success': success, 'message': message, 'can_force': True}

        return json_dumpb(data)

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /push_tx/
            Expects 'hex_tx' as args parameter that is the hex representation of the whole tx

            :rtype: string (json)

            This resource will be deprecated soon
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')
        parsed = parse_get_arguments(request.args, ARGS)
        if not parsed['success']:
            data = {'success': False, 'message': 'Missing hexadecimal data', 'can_force': False}
            return json_dumpb(data)

        data = parsed['args']
        data['force'] = b'force' in request.args and request.args[b'force'][0].decode('utf-8') == 'true'

        return self.handle_push_tx(data)

    def render_POST(self, request: Request) -> bytes:
        """ POST request for /push_tx/
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        error_ret = json_dumpb({'success': False, 'message': 'Missing hexadecimal data', 'can_force': False})
        body_content = request.content.read()
        if not body_content:
            return error_ret

        data = json_loadb(body_content)

        # Need to do that because json_loadb returns an object, which is not compatible with Dict[str, Any]
        data = cast(Dict[str, Any], data)

        if 'hex_tx' not in data:
            return error_ret

        return self.handle_push_tx(data)

    def render_OPTIONS(self, request: Request) -> int:
        return render_options(request)


PushTxResource.openapi = {
    '/push_tx': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s'
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
        'post': {
            'tags': ['transaction'],
            'operationId': 'push_tx',
            'summary': 'Push transaction to the network',
            'requestBody': {
                'description': 'Transaction to be pushed in hexadecimal',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'string',
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
                                        'success': True
                                    }
                                },
                                'error1': {
                                    'summary': 'Transaction invalid',
                                    'value': {
                                        'success': False,
                                        'message': 'This transaction is invalid.',
                                        'can_force': False
                                    }
                                },
                                'error2': {
                                    'summary': 'Error propagating transaction',
                                    'value': {
                                        'success': False,
                                        'message': 'Error message',
                                        'can_force': True
                                    }
                                },
                                'error3': {
                                    'summary': 'Double spending error',
                                    'value': {
                                        'success': False,
                                        'message': ('Invalid transaction. At least one of your inputs has'
                                                    'already been spent.')
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
