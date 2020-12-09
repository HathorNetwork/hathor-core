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

import json
from json.decoder import JSONDecodeError
from typing import Optional

from structlog import get_logger
from twisted.internet.defer import inlineCallbacks, succeed
from twisted.internet.task import deferLater
from twisted.web import resource
from twisted.web.client import Agent, HTTPConnectionPool, readBody
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer
from zope.interface import implementer

from hathor.api_util import render_options, set_cors
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.daa import minimum_tx_weight
from hathor.exception import InvalidNewTransaction
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TxValidationError
from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
from hathor.wallet.exceptions import InputDuplicated, InsufficientFunds, InvalidAddress, PrivateKeyNotFound

settings = HathorSettings()
logger = get_logger()


@implementer(IBodyProducer)
class BytesProducer(object):
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


@register_resource
class SendTokensResource(resource.Resource):
    """ Implements a web server API to send tokens.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.log = logger.new()

    # non blocking sleep
    def sleep(self, secs):
        return deferLater(self.manager.reactor, secs, lambda: None)

    def render_POST(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        try:
            data = json.loads(request.content.read().decode('utf-8'))
        except JSONDecodeError:
            return self.return_POST(False, 'Invalid json')

        if 'outputs' not in data:
            return self.return_POST(False, 'Missing outputs')

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

        propagate = True
        if 'propagate' in data:
            propagate = data['propagate']

        inputs = []
        if 'inputs' in data:
            inputs = data['inputs']

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

        tx = self.manager.wallet.prepare_transaction(Transaction, inputs, outputs, timestamp)
        tx.storage = storage
        tx.parents = parents
        weight = data.get('weight')
        if weight is None:
            weight = minimum_tx_weight(tx)
        tx.weight = weight

        # transaction is complete, now resolve proof-of-work
        if tx.weight < 3:
            tx.resolve()
            tx.verify()
            return self._cb_tx_resolve(tx, propagate)
        else:
            self._render_POST(request, tx, propagate)
            from twisted.web.server import NOT_DONE_YET
            return NOT_DONE_YET

    @inlineCallbacks
    def _render_POST(self, request, tx, propagate):
        try:
            agent = self._create_agent()
            # submit job for mining
            job_id = yield self._submit_job(agent, tx)

            # get status
            step = 0
            while True:
                response = yield self._get_job_status(agent, job_id)
                step += 1
                if step >= 5 or response['status'] != 'mining':
                    break
                yield self.sleep(3)
            status = response['status']
            self.log.info('send_tokens', job_id=job_id, status=status)
        except Exception as e:
            self.log.error('error on send_tokens', exception=e)
            return self._err_tx_resolve(None, request)

        if status == 'done':
            tx.nonce = int(response['tx']['nonce'], base=16)
            tx.timestamp = response['tx']['timestamp']
            tx.update_hash()
            result = self._cb_tx_resolve(tx, propagate)
        else:
            result = self._err_tx_resolve(None, request)

        request.write(result)
        request.finish()

    def _create_agent(self):
        pool = HTTPConnectionPool(self.manager.reactor)
        return Agent(self.manager.reactor, pool=pool)

    @inlineCallbacks
    def _submit_job(self, agent, tx):
        body = json.dumps({
            'propagate': False,
            'add_parents': False,
            'tx': bytes(tx).hex(),
        })
        data = yield agent.request(
            b'POST',
            '{}submit-job'.format(settings.TX_MINING_URL).encode(),
            Headers({'User-Agent': ['hathor-core']}),
            BytesProducer(body.encode())).addCallback(readBody)
        self.log.debug('send_tokens', data=data.decode())
        response = json.loads(data.decode())
        job_id = response['job_id']
        self.log.info('send_tokens', job_id=job_id)
        return job_id

    @inlineCallbacks
    def _get_job_status(self, agent, job_id):
        data = yield agent.request(
            b'GET',
            '{}job-status?job-id={}'.format(settings.TX_MINING_URL, job_id).encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None).addCallback(readBody)
        response = json.loads(data.decode())
        return response

    def _cb_tx_resolve(self, tx, propagate):
        """ Called when `_render_POST_thread` finishes
        """
        message = ''
        if propagate:
            try:
                success = self.manager.propagate_tx(tx, fails_silently=False)
            except (InvalidNewTransaction, TxValidationError) as e:
                success = False
                message = str(e)
        else:
            success = True
            self.log.info('tx created, do not propagate', tx=tx.hash_hex)

        self.log.info('send_tokens', tx=tx.hash_hex)
        return self.return_POST(success, message, tx=tx)

    def _err_tx_resolve(self, reason, request):
        """ Called when an error occur in `_render_POST_thread`
        """
        message = ''
        self.log.warn('tx mining timeout')
        if hasattr(reason, 'value'):
            message = str(reason.value)
        return self.return_POST(False, message)

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
            ret['tx_hex'] = bytes(tx).hex()
        return json.dumps(ret, indent=4).encode('utf-8')

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
                                    'propagate': True,
                                    'timestamp': 1549667726
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
                                        },
                                        'tx_hex': '000100010113c990cfca448ea3750eeed4723cf4752944773b6815d51fba9e1d0'
                                                  '4d772b4cf00006b4830460221009b1dbcaf226cf5578e7f8050438abd25861f6f'
                                                  '4fb49b2d3fb92960faa8438e3a022100bbf2e439a19597e99ef3f39a5a3aba026'
                                                  '74ffcdf25108d4bde8012c223f114422103897881129e706c7561feaecd9cc8c5'
                                                  '11f8dbd1b578e0cfe2993049f5cf05ee6a00004e2000001976a9148362a4406c9'
                                                  '76579057b1b98fbdca03e30d9e04688ac3ff00000000000005fd14af50249519c'
                                                  '7995b84ba6a547485302c04b4ae8bd1771bb102d23e75d9e28ab5d739c71b8dc0'
                                                  'd1334a6731f7152459c713204d7ebcf15d442b68ea0171462063bbe8200000002'
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
