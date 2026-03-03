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

from typing import Any, Optional, Union

from twisted.internet import threads
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.utils import Features
from hathor.manager import HathorManager
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TxValidationError
from hathor.util import json_dumpb, json_loadb
from hathor.verification.verification_params import VerificationParams
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InputDuplicated, InsufficientFunds, InvalidAddress, PrivateKeyNotFound


@register_resource
class SendTokensResource(Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: HathorManager, settings: HathorSettings) -> None:
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self._settings = settings

    def render_POST(self, request):
        """ POST request for /wallet/send_tokens/
            We expect 'data' as request args
            'data': stringified json with an array of inputs and array of outputs
            If inputs array is empty we use 'prepare_compute_inputs', that calculate the inputs
            We return success (bool)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        post_data = json_loadb(request.content.read())
        data = post_data['data']

        outputs = []
        for output in data['outputs']:
            try:
                address = decode_address(output['address'])  # bytes
            except InvalidAddress:
                return self.return_POST(False, 'The address {} is invalid'.format(output['address']))

            value = int(output['value'])
            timelock = output.get('timelock')
            token_uid = output.get('token_uid')
            if token_uid:
                outputs.append(WalletOutputInfo(address=address, value=value, timelock=timelock, token_uid=token_uid))
            else:
                outputs.append(WalletOutputInfo(address=address, value=value, timelock=timelock))

        timestamp = None
        if 'timestamp' in data:
            if data['timestamp'] > 0:
                timestamp = data['timestamp']
            else:
                timestamp = int(self.manager.reactor.seconds())

        if len(data['inputs']) == 0:
            try:
                inputs, outputs = self.manager.wallet.prepare_compute_inputs(outputs, self.manager.tx_storage,
                                                                             timestamp)
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
                inputs = self.manager.wallet.prepare_incomplete_inputs(inputs, self.manager.tx_storage)
            except (PrivateKeyNotFound, InputDuplicated):
                return self.return_POST(False, 'Invalid input to create transaction')

        storage = self.manager.tx_storage
        if timestamp is None:
            max_ts_spent_tx = max(storage.get_transaction(txin.tx_id).timestamp for txin in inputs)
            timestamp = max(max_ts_spent_tx + 1, int(self.manager.reactor.seconds()))
        parents = self.manager.get_new_tx_parents(timestamp)

        values = {
            'inputs': inputs,
            'outputs': outputs,
            'storage': storage,
            'weight': data.get('weight'),
            'parents': parents,
            'timestamp': timestamp,
        }

        deferred = threads.deferToThread(self._render_POST_thread, values, request)
        deferred.addCallback(self._cb_tx_resolve, request)
        deferred.addErrback(self._err_tx_resolve, request)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _render_POST_thread(self, values: dict[str, Any], request: Request) -> Union[bytes, Transaction]:
        assert self.manager.wallet is not None
        tx = self.manager.wallet.prepare_transaction(Transaction, values['inputs'],
                                                     values['outputs'], values['timestamp'])
        tx.storage = values['storage']
        tx.parents = values['parents']
        weight = values['weight']
        if weight is None:
            weight = self.manager.daa.minimum_tx_weight(tx)
        tx.weight = weight
        self.manager.cpu_mining_service.resolve(tx)
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        best_block = self.manager.tx_storage.get_best_block()
        features = Features.from_vertex(
            settings=self._settings,
            feature_service=self.manager.feature_service,
            vertex=best_block,
        )
        params = VerificationParams.default_for_mempool(best_block=best_block, features=features)
        self.manager.verification_service.verify(tx, params)
        return tx

    def _cb_tx_resolve(self, tx, request):
        """ Called when `_render_POST_thread` finishes
        """
        message = ''
        try:
            success = self.manager.propagate_tx(tx)
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
        return json_dumpb(ret)

    def render_OPTIONS(self, request):
        return render_options(request)


SendTokensResource.openapi = {
    '/wallet/send_tokens': {
        'x-visibility': 'private',
        'post': {
            'tags': ['private_wallet'],
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
                                            'parents': [],
                                            'inputs': [],
                                            'outputs': [],
                                            'tokens': [],
                                            'accumulated_weight': 14.0,
                                            'accumulated_weight_raw': '16384'
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
