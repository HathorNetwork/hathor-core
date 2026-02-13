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
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional

from structlog import get_logger
from twisted.internet import threads
from twisted.internet.defer import CancelledError, Deferred
from twisted.python.failure import Failure
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, render_options, set_cors
from hathor.conf.get_settings import get_global_settings
from hathor.exception import InvalidNewTransaction
from hathor.reactor import get_global_reactor
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TxValidationError
from hathor.util import json_dumpb, json_loadb
from hathor.verification.verification_params import VerificationParams

logger = get_logger()

# Timeout for the pow resolution in stratum (in seconds)
TIMEOUT_STRATUM_RESOLVE_POW = 20


@dataclass
class _Context:
    tx: Transaction
    request: Request
    should_stop_mining_thread: bool = False


@register_resource
class SendTokensResource(Resource):
    """ Implements a web server API to create a tx and propagate

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self._settings = get_global_settings()
        self.manager = manager
        self.sleep_seconds = 0
        self.log = logger.new()
        self.reactor = get_global_reactor()

    def render_POST(self, request: Request) -> Any:
        """ POST request for /thin_wallet/send_tokens/
            We expect 'tx_hex' as request args
            'tx_hex': serialized tx in hexadecimal
            We return success (bool)

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        # Validating if we still have unused threads to solve the pow
        if len(self.manager.pow_thread_pool.working) == self._settings.MAX_POW_THREADS:
            return self.return_POST(
                False,
                'The server is currently fully loaded to send tokens. Wait a moment and try again, please.',
                return_code='max_pow_threads'
            )

        assert request.content is not None
        raw_data = request.content.read()

        if raw_data is None:
            return self.return_POST(
                False,
                'Missing POST data JSON',
                return_code='missing_json'
            )

        try:
            post_data = json_loadb(raw_data)
        except AttributeError:
            return self.return_POST(
                False,
                'Missing transaction hexadecimal in POST data',
                return_code='missing_tx_data'
            )

        try:
            tx_hex = post_data['tx_hex']
        except KeyError:
            return self.return_POST(
                False,
                'Missing \'tx_hex\' parameter',
                return_code='missing_tx_hex_param'
            )

        try:
            tx = self.manager.vertex_parser.deserialize(bytes.fromhex(tx_hex))
        except (ValueError, struct.error):
            # ValueError: invalid hex
            # struct.error: invalid transaction data
            return self.return_POST(
                False,
                'Error parsing hexdump to create the transaction',
                return_code='param_invalid_hex'
            )

        assert isinstance(tx, Transaction)
        # Set tx storage
        tx.storage = self.manager.tx_storage

        # If this tx is a double spending, don't even try to propagate in the network
        is_double_spending = tx.is_double_spending()
        if is_double_spending:
            return self.return_POST(
                False,
                'Invalid transaction. At least one of your inputs has already been spent.',
                return_code='double_spending'
            )

        context = _Context(tx=tx, request=request)

        if self._settings.SEND_TOKENS_STRATUM and self.manager.stratum_factory:
            self._render_POST_stratum(context)
        else:
            self._render_POST(context)

        request.notifyFinish().addErrback(self._responseFailed, context)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _render_POST_stratum(self, context: _Context) -> None:
        """ Resolves the request using stratum
            Create a deferred and send it and the tx to be mined to stratum
            WHen the proof of work is completed in stratum, the callback is called
        """
        tx = context.tx
        request = context.request

        # When using stratum to solve pow, we already set timestamp and parents
        stratum_deferred: Deferred[None] = Deferred()
        # FIXME: Skipping mypy on the lines below for now, as it looks like it's wrong but we don't have tests for it.
        stratum_deferred.addCallback(self._stratum_deferred_resolve, request)  # type: ignore[call-overload]
        fn_timeout = partial(self._stratum_timeout, request=request, tx=tx)  # type: ignore[call-arg]
        stratum_deferred.addTimeout(TIMEOUT_STRATUM_RESOLVE_POW, self.manager.reactor, onTimeoutCancel=fn_timeout)

        # this prepares transaction for mining
        self.manager.stratum_factory.mine_transaction(tx, stratum_deferred)
        # process it right away
        self.manager.stratum_factory.update_jobs()

    def _render_POST(self, context: _Context) -> None:
        """ Resolves the request without stratum
            The transaction is completed and then sent to be mined in a thread
        """
        tx = context.tx

        if tx.inputs:
            max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
            # Set tx timestamp as max between tx and inputs
            tx.timestamp = max(max_ts_spent_tx + 1, tx.timestamp)

        # Set parents
        tx.parents = self.manager.get_new_tx_parents(tx.timestamp)

        deferred = threads.deferToThreadPool(self.reactor, self.manager.pow_thread_pool,
                                             self._render_POST_thread, context)
        deferred.addCallback(self._cb_tx_resolve)
        deferred.addErrback(self._err_tx_resolve, context, 'python_resolve')

    def _responseFailed(self, err, context):
        # response failed, should stop mining
        tx = context.tx
        self.log.warn('connection closed while resolving transaction proof of work', tx=tx)
        if self._settings.SEND_TOKENS_STRATUM and self.manager.stratum_factory:
            funds_hash = tx.get_funds_hash()
            self._cleanup_stratum(funds_hash)
            # start new job in stratum, so the miner doesn't waste more time on this tx
            self.manager.stratum_factory.update_jobs()
        else:
            # if we're mining on a thread, stop it
            context.should_stop_mining_thread = True

    def _stratum_deferred_resolve(self, context: _Context) -> None:
        """ Method called after stratum resolves tx proof of work
            We remove the mining data of this tx on stratum and start a new thread to verify the tx
        """
        funds_hash = context.tx.get_funds_hash()
        context.tx = self.manager.stratum_factory.mined_txs[funds_hash]
        # Delete it to avoid memory leak
        del self.manager.stratum_factory.mined_txs[funds_hash]

        deferred = threads.deferToThreadPool(self.reactor, self.manager.pow_thread_pool,
                                             self._stratum_thread_verify, context)
        deferred.addCallback(self._cb_tx_resolve)
        deferred.addErrback(self._err_tx_resolve, context, 'stratum_resolve')

    def _stratum_thread_verify(self, context: _Context) -> _Context:
        """ Method to verify the transaction that runs in a separated thread
        """
        best_block = self.manager.tx_storage.get_best_block()
        params = VerificationParams.default_for_mempool(best_block=best_block)
        self.manager.verification_service.verify(context.tx, params)
        return context

    def _stratum_timeout(self, result: Failure, timeout: int, *, context: _Context) -> None:
        """ Method called when stratum timeouts when trying to solve tx pow
            We remove mining data and deferred from stratum and send error as response
        """
        stratum_tx = None
        tx = context.tx
        funds_hash = tx.get_funds_hash()

        # We get both tx because stratum might have updated the tx (timestamp or parents)
        stratum_tx = self._cleanup_stratum(funds_hash)

        result.value = 'Timeout: error resolving transaction proof of work'

        from hathor.transaction.vertex_parser import vertex_serializer
        self.log.warn('stratum timeout: error resolving transaction proof of work',
                      tx=vertex_serializer.serialize(tx).hex(),
                      stratum_tx=vertex_serializer.serialize(stratum_tx).hex() if stratum_tx else '')

        # start new job in stratum, so the miner doesn't waste more time on this tx
        self.manager.stratum_factory.update_jobs()

        # update metrics
        self.manager.metrics.send_token_timeouts += 1

        self._err_tx_resolve(result, context, 'stratum_timeout')

    def _cleanup_stratum(self, funds_hash: bytes) -> Optional[Transaction]:
        """ Cleans information on stratum factory related to this transaction
        """
        stratum_tx = None
        if funds_hash in self.manager.stratum_factory.mining_tx_pool:
            stratum_tx = self.manager.stratum_factory.mining_tx_pool.pop(funds_hash)

        if funds_hash in self.manager.stratum_factory.deferreds_tx:
            del self.manager.stratum_factory.deferreds_tx[funds_hash]

        if funds_hash in self.manager.stratum_factory.tx_queue:
            self.manager.stratum_factory.tx_queue.remove(funds_hash)

        return stratum_tx

    def _render_POST_thread(self, context: _Context) -> _Context:
        """ Method called in a thread to solve tx pow without stratum
        """
        # TODO Tx should be resolved in the frontend
        def _should_stop():
            return context.should_stop_mining_thread
        self.manager.cpu_mining_service.start_mining(
            context.tx,
            sleep_seconds=self.sleep_seconds,
            should_stop=_should_stop
        )
        if context.should_stop_mining_thread:
            raise CancelledError()
        context.tx.update_hash()
        context.tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        best_block = self.manager.tx_storage.get_best_block()
        params = VerificationParams.default_for_mempool(best_block=best_block)
        self.manager.verification_service.verify(context.tx, params)
        return context

    def _cb_tx_resolve(self, context: _Context) -> None:
        """ Called when `_render_POST_thread` finishes
        """
        tx = context.tx
        request = context.request
        message = ''
        return_code = ''
        try:
            success = self.manager.propagate_tx(tx)
            if success:
                return_code = 'success'
            else:
                return_code = 'propagating_error'
        except (InvalidNewTransaction, TxValidationError) as e:
            success = False
            message = str(e)
            return_code = 'propagating_error'

        result = self.return_POST(success, message, tx=tx, return_code=return_code)

        request.write(result)
        request.finish()

    def _err_tx_resolve(self, reason, context, return_code):
        """ Called when an error occur in `_render_POST_thread`
        """
        request = context.request
        message = ''
        if hasattr(reason, 'value'):
            message = str(reason.value)
        result = self.return_POST(False, message, return_code=return_code)
        request.write(result)
        request.finish()

    def return_POST(self,
                    success: bool,
                    message: str,
                    tx: Optional[Transaction] = None,
                    return_code: str = '') -> bytes:
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
            'return_code': return_code,
        }
        if tx:
            ret['tx'] = tx.to_json()

        return json_dumpb(ret)

    def render_OPTIONS(self, request):
        return render_options(request)


SendTokensResource.openapi = {
    '/thin_wallet/send_tokens': {
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
            'tags': ['wallet'],
            'operationId': 'send_tokens',
            'summary': 'Send tokens',
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
                                    'return_code': 'stratum_resolve',
                                    'value': {
                                        'success': False,
                                        'message': 'The address abc is invalid'
                                    }
                                },
                                'error2': {
                                    'summary': 'Insufficient funds',
                                    'return_code': 'python_resolve',
                                    'value': {
                                        'success': False,
                                        'message': 'Insufficient funds'
                                    }
                                },
                                'error3': {
                                    'summary': 'Invalid input',
                                    'return_code': 'python_resolve',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid input to create transaction'
                                    }
                                },
                                'error4': {
                                    'summary': 'Propagation error',
                                    'value': {
                                        'success': False,
                                        'return_code': 'propagating_error',
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
                                            'accumulated_weight': 14.0,
                                            'accumulated_weight_raw': '16384'
                                        }
                                    }
                                },
                                'error5': {
                                    'summary': 'Double spending error',
                                    'value': {
                                        'success': False,
                                        'return_code': 'double_spending',
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
