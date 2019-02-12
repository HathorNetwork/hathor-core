import json
from threading import Lock
from typing import Optional

from twisted.internet import threads
from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.crypto.util import decode_address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.base_transaction import int_to_bytes
from hathor.transaction.scripts import P2PKH, create_output_script
from hathor.wallet.exceptions import InvalidAddress


@register_resource
class SendTokensResource(resource.Resource):
    """ Implements a web server API to create a tx and propagate

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.lock = Lock()

    def _render_POST_thread(self, request: Request) -> bytes:
        """ POST request for /thin_wallet/send_tokens/
            We expect 'data' as request args
            'data': stringified json with an array of inputs and array of outputs
            We return success (bool) and the data_to_sign

            :rtype: string (json)
        """
        with self.lock:
            request.setHeader(b'content-type', b'application/json; charset=utf-8')
            set_cors(request, 'POST')

            post_data = json.loads(request.content.read().decode('utf-8'))
            data = post_data['data']

            outputs = []
            for output in data['outputs']:
                try:
                    address = decode_address(output['address'])  # bytes
                except InvalidAddress:
                    return self.return_POST(False, 'The address {} is invalid'.format(output['address']))

                value = int(output['value'])
                timelock_value = output.get('timelock')
                timelock = int_to_bytes(int(timelock_value), 4) if timelock_value else None
                # XXX Fixing token_index to 0
                outputs.append(TxOutput(value, create_output_script(address, timelock), 0))

            inputs = []
            for input_tx in data['inputs']:
                index = int(input_tx['index'])
                tx_id = bytes.fromhex(input_tx['tx_id'])
                signature = bytes.fromhex(input_tx['signature'])
                public_key_bytes = bytes.fromhex(input_tx['public_key'])
                input_data = P2PKH.create_input_data(public_key_bytes, signature)
                inputs.append(TxInput(tx_id, index, input_data))

            tx = Transaction(outputs=outputs, inputs=inputs)
            tx.storage = self.manager.tx_storage

            max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
            tx.timestamp = max(max_ts_spent_tx + 1, int(self.manager.reactor.seconds()))
            tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
            tx.weight = self.manager.minimum_tx_weight(tx)

        # There is no need to synchonize this slow part.
        # TODO Tx should be resolved in the frontend
        tx.resolve()

        # Then, we synchonize again.
        with self.lock:
            success, message = tx.validate_tx_error()
            if success:
                success = self.manager.propagate_tx(tx)

        return self.return_POST(success, message, tx=tx)

    def render_POST(self, request: Request):
        deferred = threads.deferToThread(self._render_POST_thread, request)
        deferred.addCallback(self._cb_tx_resolve, request)
        deferred.addErrback(self._err_tx_resolve, request)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _cb_tx_resolve(self, result, request):
        """ Called when `_render_POST_thread` finishes
        """
        request.write(result)
        request.finish()

    def _err_tx_resolve(self, reason, request):
        """ Called when an error occur in `_render_POST_thread`
        """
        request.processingFailed(reason)

    def return_POST(self, success: bool, message: str, tx: Optional[Transaction] = None) -> bytes:
        """ Auxiliar method to return result of POST method

            :param success: If tx was created successfully
            :type success: bool

            :param message: Message in case of error
            :type success: string

            :rtype: string (json)
        """
        ret = {
            'success': success,
            'message': message,
        }
        if tx:
            ret['tx'] = tx.to_json()
        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        return render_options(request)


SendTokensResource.openapi = {
    '/thin_wallet/send_tokens': {
        'post': {
            'tags': ['thin_wallet'],
            'operationId': 'thin_wallet_send_tokens',
            'summary': 'Send tokens in a thin wallet',
            'requestBody': {
                'description': 'Data to create transactions',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ThinWalletSendToken'
                        },
                        'examples': {
                            'data': {
                                'summary': 'Data to create transactions',
                                'value': {
                                    'data': {
                                        'outputs': [
                                            {
                                                'address': '15VZc2jy1L3LGFweZeKVbWMsTzfKFJLpsN',
                                                'value': 1000
                                            },
                                            {
                                                'address': '1C5xEjewerH4zTWPC6wqzhoEkMhiHEHPZ8',
                                                'value': 800
                                            }
                                        ],
                                        'inputs': [
                                            {
                                                'tx_id': ('00000257054251161adff5899a451ae9'
                                                          '74ac62ca44a7a31179eec5750b0ea406'),
                                                'index': 0,
                                                'signature': '00000257054251161adff5899a451ae9',
                                                'public_key': '74ac62ca44a7a31179eec5750b0ea406',
                                            }
                                        ]
                                    }
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
                                        'message': '',
                                        'tx': {
                                            'hash': '00000c064ec72c8561a24b65bd50095a401b8d9a66c360cfe99cfcfeed73afc4',
                                            'nonce': 2979,
                                            'timestamp': 1547211690,
                                            'version': 1,
                                            'weight': 17.93619278054934,
                                            'height': 0,
                                            'parents': [
                                                '00000257054251161adff5899a451ae974ac62ca44a7a31179eec5750b0ea406',
                                                '00000b8792cb13e8adb51cc7d866541fc29b532e8dec95ae4661cf3da4d42cb4'
                                            ],
                                            'inputs': [
                                                {
                                                    'tx_id': ('00000257054251161adff5899a451ae9'
                                                              '74ac62ca44a7a31179eec5750b0ea406'),
                                                    'index': 0,
                                                    'data': ('RzBFAiAh6Jq+HOn9laOq3A5uUcaGLdWB4gM6RehsaP9OIMrOrwIhAOjW'
                                                             'T+4ceSQI8CNXqaNNJgaOzCDhmFF1z1rhxOMCgonxIQNhXZKwBZeKxJps'
                                                             'JEqP4gIS4FFbEpG284HhmBfp1p5gUw==')
                                                }
                                            ],
                                            'outputs': [
                                                {
                                                    'value': 1109,
                                                    'script': 'dqkUMUdd0fmGCmGfv7B5UriM5VS5g16IrA=='
                                                },
                                                {
                                                    'value': 800,
                                                    'script': 'dqkUeZkoJssEgwjPw/1ubA9XXZNk+xGIrA=='
                                                }
                                            ],
                                            'tokens': []
                                        }
                                    }
                                },
                                'error1': {
                                    'summary': 'Invalid address',
                                    'value': {
                                        'success': False,
                                        'message': 'The address abc is invalid'
                                    }
                                },
                                'error2': {
                                    'summary': 'Insufficient funds',
                                    'value': {
                                        'success': False,
                                        'message': 'Insufficient funds'
                                    }
                                },
                                'error3': {
                                    'summary': 'Invalid input',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid input to create transaction'
                                    }
                                },
                                'error4': {
                                    'summary': 'Propagation error',
                                    'value': {
                                        'success': False,
                                        'message': 'Propagation error message',
                                        'tx': {
                                            'hash': '00002b3be4e3876e67b5e090d76dcd71cde1a30ca1e54e38d65717ba131cd22f',
                                            'nonce': 17076,
                                            'timestamp': 1539271482,
                                            'version': 1,
                                            'weight': 14.0,
                                            'height': 1,
                                            'parents': [],
                                            'inputs': [],
                                            'outputs': [],
                                            'tokens': [],
                                            'accumulated_weight': 14
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
}
