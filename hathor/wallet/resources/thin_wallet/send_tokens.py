import json
from threading import Lock
from typing import Optional

from twisted.internet import threads
from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TxValidationError


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

    def render_POST(self, request: Request):
        """ POST request for /thin_wallet/send_tokens/
            We expect 'tx_hex' as request args
            'tx_hex': serialized tx in hexadecimal
            We return success (bool)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        post_data = json.loads(request.content.read().decode('utf-8'))
        tx_hex = post_data['tx_hex']

        tx = Transaction.create_from_struct(bytes.fromhex(tx_hex))
        assert isinstance(tx, Transaction)
        # Set tx storage
        tx.storage = self.manager.tx_storage

        max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
        # Set tx timestamp as max between tx and inputs
        tx.timestamp = max(max_ts_spent_tx + 1, tx.timestamp)
        # Set parents
        tx.parents = self.manager.get_new_tx_parents(tx.timestamp)

        deferred = threads.deferToThread(self._render_POST_thread, tx, request)
        deferred.addCallback(self._cb_tx_resolve, request)
        deferred.addErrback(self._err_tx_resolve, request)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _render_POST_thread(self, tx: Transaction, request: Request) -> Transaction:
        # TODO Tx should be resolved in the frontend
        tx.resolve()
        tx.verify()
        return tx

    def _cb_tx_resolve(self, tx, request):
        """ Called when `_render_POST_thread` finishes
        """
        message = ''
        try:
            success = self.manager.propagate_tx(tx, fails_silently=False)
        except (InvalidNewTransaction, TxValidationError) as e:
            success = False
            message = str(e)

        result = self.return_POST(success, message, tx=tx)

        request.write(result)
        request.finish()

    def _err_tx_resolve(self, reason, request):
        """ Called when an error occur in `_render_POST_thread`
        """
        message = ''
        if hasattr(reason, 'value'):
            message = str(reason.value)
        result = self.return_POST(False, message)
        request.write(result)
        request.finish()

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
                'description': 'Data to create the transaction',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ThinWalletSendToken'
                        },
                        'examples': {
                            'data': {
                                'summary': 'Data to create the transaction',
                                'value': {
                                    'tx_hex': '00000c064ec72c8561a24b65bd50095a401b8d9a66c360cfe99cfcfeed73afc4',
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
