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

import struct
from json import JSONDecodeError
from typing import TYPE_CHECKING, Any, Optional, cast

from structlog import get_logger
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, parse_args, render_options, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TxValidationError
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from hathor.manager import HathorManager

logger = get_logger()

ARGS = ['hex_tx']


@register_resource
class PushTxResource(Resource):
    """ Implements a web server API that receives hex form of a tx and send it to the network

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager', max_output_script_size: Optional[int] = None,
                 allow_non_standard_script: bool = False) -> None:
        self._settings = get_global_settings()
        self.log = logger.new()
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.max_output_script_size: int = (
            self._settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE
            if max_output_script_size is None else
            max_output_script_size
        )
        self.allow_non_standard_script = allow_non_standard_script

    def _get_client_ip(self, request: 'Request') -> str:
        x_real_ip = request.getHeader('X-Real-IP')
        if x_real_ip:
            return x_real_ip.strip()
        x_forwarded_for = request.getHeader('X-Forwarded-For')
        if x_forwarded_for:
            return x_forwarded_for.split(',', 1)[0].strip()
        addr = request.getClientAddress()
        return getattr(addr, 'host', 'unknown')

    def handle_push_tx(self, params: dict[str, Any], client_addr: str) -> dict[str, Any]:
        try:
            tx_bytes = bytes.fromhex(params['hex_tx'])
            tx = self.manager.vertex_parser.deserialize(tx_bytes)
        except ValueError:
            return {'success': False, 'message': 'Invalid hexadecimal data', 'can_force': False}
        except struct.error:
            return {
                'success': False,
                'message': 'This transaction is invalid. Try to decode it first to validate it.',
                'can_force': False
            }

        self.log.info('push tx', client=client_addr, tx=tx)

        if tx.is_block:
            # It's a block and we can't push blocks
            return {
                'success': False,
                'message': 'This transaction is invalid. A transaction must have at least one input',
                'can_force': False
            }

        tx.storage = self.manager.tx_storage
        # If this tx is a double spending, don't even try to propagate in the network
        assert isinstance(tx, Transaction)

        # Try to push the tx.
        message = ''
        success = True
        try:
            self.manager.push_tx(tx, allow_non_standard_script=self.allow_non_standard_script,
                                 max_output_script_size=self.max_output_script_size)
        except (InvalidNewTransaction, TxValidationError) as e:
            success = False
            message = str(e)
            self.log.warn('push tx rejected', reason=repr(e))
        data = {'success': success, 'message': message}
        if success:
            data['tx'] = tx.to_json()
        return data

    def render_GET(self, request: Request) -> bytes:
        """ GET request for /push_tx/
            Expects 'hex_tx' as args parameter that is the hex representation of the whole tx

            :rtype: string (json)

            This resource will be deprecated soon
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')
        args = get_args(request)
        parsed = parse_args(args, ARGS)
        if not parsed['success']:
            data = {'success': False, 'message': 'Missing hexadecimal data', 'can_force': False}
            return json_dumpb(data)

        data = parsed['args']
        data['force'] = b'force' in args and args[b'force'][0].decode('utf-8') == 'true'

        ret = self.handle_push_tx(data, self._get_client_ip(request))
        return json_dumpb(ret)

    def render_POST(self, request: Request) -> bytes:
        """ POST request for /push_tx/
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        error_ret = json_dumpb({'success': False, 'message': 'Missing hexadecimal data', 'can_force': False})
        assert request.content is not None
        body_content = request.content.read()
        if not body_content:
            return error_ret

        try:
            data = json_loadb(body_content)
        except JSONDecodeError as exc:
            return json_dumpb({
                'success': False,
                'message': str(exc),
            })

        if not isinstance(data, dict):
            return error_ret

        # Need to do that because json_loadb returns an object, which is not compatible with dict[str, Any]
        data = cast(dict[str, Any], data)

        if 'hex_tx' not in data:
            return error_ret

        ret = self.handle_push_tx(data, self._get_client_ip(request))
        return json_dumpb(ret)

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
                            'type': 'object',
                            'properties': {
                                'hex_tx': 'string',
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
        },
        'get': {
            'tags': ['transaction'],
            'operationId': 'push_tx',
            'summary': 'Push transaction to the network',
            'parameters': [
                {
                    'name': 'hex_tx',
                    'in': 'query',
                    'description': 'Transaction to be pushed in hexadecimal',
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
