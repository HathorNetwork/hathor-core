import json
from threading import Lock
from typing import Optional

from twisted.internet import threads
from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.transaction import Transaction
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InputDuplicated, InsufficientFunds, InvalidAddress, PrivateKeyNotFound


@register_resource
class SendTokensResource(resource.Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.lock = Lock()

    def _render_POST_thread(self, request: Request) -> bytes:
        """ POST request for /wallet/send_tokens/
            We expect 'data' as request args
            'data': stringified json with an array of inputs and array of outputs
            If inputs array is empty we use 'prepare_transaction_compute_inputs', that calculate the inputs
            We return success (bool)

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
                    address = self.manager.wallet.decode_address(output['address'])  # bytes
                except InvalidAddress:
                    return self.return_POST(False, 'The address {} is invalid'.format(output['address']))

                value = int(output['value'])
                timelock = output.get('timelock')
                outputs.append(WalletOutputInfo(address=address, value=value, timelock=timelock))

            timestamp = None
            if 'timestamp' in data:
                if data['timestamp'] > 0:
                    timestamp = data['timestamp']
                else:
                    timestamp = int(self.manager.reactor.seconds())

            if len(data['inputs']) == 0:
                try:
                    tx = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, timestamp)
                except InsufficientFunds as e:
                    return self.return_POST(False, 'Insufficient funds, {}'.format(str(e)))
            else:
                inputs = []
                for input_tx in data['inputs']:
                    input_tx['private_key'] = None
                    input_tx['index'] = int(input_tx['index'])
                    input_tx['tx_id'] = bytes.fromhex(input_tx['tx_id'])
                    inputs.append(WalletInputInfo(**input_tx))
                try:
                    tx = self.manager.wallet.prepare_transaction_incomplete_inputs(Transaction, inputs, outputs,
                                                                                   self.manager.tx_storage, timestamp)
                except (PrivateKeyNotFound, InputDuplicated):
                    return self.return_POST(False, 'Invalid input to create transaction')

            tx.storage = self.manager.tx_storage
            # TODO Send tx to be mined

            if timestamp is None:
                max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
                tx.timestamp = max(max_ts_spent_tx + 1, int(self.manager.reactor.seconds()))
            tx.parents = self.manager.get_new_tx_parents(tx.timestamp)

            # Calculating weight
            weight = data.get('weight')
            if weight is None:
                weight = self.manager.minimum_tx_weight(tx)
            tx.weight = weight

        # There is no need to synchonize this slow part.
        tx.resolve()

        # Then, we synchonize again.
        with self.lock:
            success, message = tx.validate_tx_error()
            if success:
                success = self.manager.propagate_tx(tx)

        return self.return_POST(success, message, tx=tx)

    def render_POST(self, request):
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
    '/wallet/send_tokens': {
        'post': {
            'tags': ['wallet'],
            'operationId': 'wallet_send_tokens',
            'summary': 'Send tokens',
            'requestBody': {
                'description': 'Data to create transactions',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/SendToken'
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
                                                'index': 0
                                            }
                                        ],
                                        'timestamp': 1549667726
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
                                        'message': 'Insufficient funds. Requested amount: 200 / Available: 50'
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
