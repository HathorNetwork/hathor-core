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

"""
The coordinator is fairly contained (could even be spun off to a separate project).

Asyncio with async/await is much more ergonomic and less cumbersome than twisted, so it was easier/faster to use it.
"""

import asyncio
import time
from itertools import count
from typing import Any, Callable, Iterator, NamedTuple, Optional, Union
from uuid import uuid4

import aiohttp
from structlog import get_logger

from hathor.client import IHathorClient, IMiningChannel
from hathor.crypto.util import decode_address
from hathor.difficulty import Hash, PDiff, Target, Weight
from hathor.merged_mining.bitcoin import (
    BitcoinBlock,
    BitcoinBlockHeader,
    BitcoinRawTransaction,
    BitcoinTransaction,
    BitcoinTransactionInput,
    BitcoinTransactionOutput,
    build_merkle_path_for_coinbase,
    build_merkle_root,
    build_merkle_root_from_path,
    encode_bytearray,
    encode_uint32,
)
from hathor.merged_mining.bitcoin_rpc import IBitcoinRPC
from hathor.merged_mining.util import Periodic
from hathor.transaction import BitcoinAuxPow, MergeMinedBlock, MergeMinedBlock as HathorBlock
from hathor.transaction.exceptions import ScriptError, TxValidationError
from hathor.util import MaxSizeOrderedDict, Random, ichunks

logger = get_logger()


MAGIC_NUMBER = b'Hath'  # bytes.fromhex('48617468') or 0x68746148.to_bytes(4, 'little')
NICEHASH_MIN_DIFF = 500_000  # as per https://www.nicehash.com/pool-operators

UNRECOVERABLE_ERROR_CODE_MAX = -32600

PARSE_ERROR = {'code': -32700, 'message': 'Parse error'}
# INTERNAL_ERROR = {'code': -32603, 'message': 'Internal error'}
INVALID_PARAMS = {'code': -32602, 'message': 'Invalid params'}
METHOD_NOT_FOUND = {'code': -32601, 'message': 'Method not found'}
INVALID_REQUEST = {'code': -32600, 'message': 'Invalid Request'}

NODE_SYNCING = {'code': 10, 'message': 'Node syncing'}
# INVALID_ADDRESS = {'code': 22, 'message': 'Address to send mined funds is invalid'}
INVALID_SOLUTION = {'code': 30, 'message': 'Invalid solution'}
# STALE_JOB = {'code': 31, 'message': 'Stale job submitted'}
JOB_NOT_FOUND = {'code': 32, 'message': 'Job not found'}
# PROPAGATION_FAILED = {'code': 33, 'message': 'Solution propagation failed'}
DUPLICATE_SOLUTION = {'code': 34, 'message': 'Solution already submitted'}

ZEROED_4: bytes = b'\0' * 4
ZEROED_32: bytes = b'\0' * 32


class HathorCoordJob(NamedTuple):
    """ Data class used to send a job's work to Hathor Stratum.
    """
    block: HathorBlock
    height: Optional[int]

    def to_dict(self) -> dict[Any, Any]:
        d = self.block.to_json()
        d['height'] = self.height
        return d


def flip80(data: bytes) -> bytes:
    """ Reverse the order of every 4 bytes.

    Input size must be multiple of 4.

    This function is used because miners expect some data to be flipped this way, and is named after the function that
    most mining implementations use.

    Examples:

    >>> flip80(bytes.fromhex('00000000faf35c4ce3016ed0e37c34a11c405f32e34177f5a9fe3791686fc621')).hex()
    '000000004c5cf3fad06e01e3a1347ce3325f401cf57741e39137fea921c66f68'
    """
    if len(data) % 4 != 0:
        raise ValueError('data must have a size multiple of 4')
    return b''.join(x[::-1] for x in ichunks(data, 4))


def parse_login_with_addresses(login: str) -> tuple[bytes, bytes, Optional[str]]:
    """ Parses a login of the form HATHOR_ADDRESS.BITCOIN_ADDRESS[.WORKER_NAME] returns output scripts and worker name.

    Examples:

    >>> out = parse_login_with_addresses('HC7w4j7mPet49BBN5a2An3XUiPvK6C1TL7.1Mtb6rphrRq6kUdxpzQCUXZBaMbNpM3ZCN')
    >>> out[0].hex(), out[1].hex(), out[2]
    ('76a9143d6dbcbf6e67b2cbcc3225994756a56a5e2d3a2788ac', '76a914e52432216dabf32d60a02894ec871293baaa1b1288ac', None)
    >>> out = parse_login_with_addresses('HC7w4j7mPet49BBN5a2An3XUiPvK6C1TL7.1Mtb6rphrRq6kUdxpzQCUXZBaMbNpM3ZCN.foo')
    >>> out[0].hex(), out[1].hex(), out[2]
    ('76a9143d6dbcbf6e67b2cbcc3225994756a56a5e2d3a2788ac', '76a914e52432216dabf32d60a02894ec871293baaa1b1288ac', 'foo')
    """
    from hathor.merged_mining.bitcoin import create_output_script as create_output_script_btc
    from hathor.transaction.scripts import create_output_script as create_output_script_htr
    parts = login.split('.', maxsplit=2)
    if len(parts) < 2:
        raise ValueError(
            'Expected `{{HTR_ADDR}}.{{BTC_ADDR}}` or `{{HTR_ADDR}}.{{BTC_ADDR}}.{{WORKER}}` got "{}"'.format(login))
    payback_address_hathor = parts[0]
    payback_address_bitcoin = parts[1]
    payback_script_hathor = create_output_script_htr(decode_address(payback_address_hathor))
    payback_script_bitcoin = create_output_script_btc(decode_address(payback_address_bitcoin))
    worker_name = parts[2] if len(parts) > 2 else None
    return payback_script_hathor, payback_script_bitcoin, worker_name


class SingleMinerWork(NamedTuple):
    """ Work submitted by a miner, result from a SingleMinerJob.
    """

    job_id: str
    nonce: int
    xnonce1: bytes  # not submitted by miner
    xnonce2: bytes
    timestamp: Optional[int] = None

    @classmethod
    def from_stratum_params(cls, xnonce1: bytes, params: list) -> 'SingleMinerWork':
        """ Parse params received from Stratum and instantiate work accordingly.
        """
        from hathor.merged_mining.bitcoin import read_uint32
        if len(params) == 5:
            _rpc_user, job_id, raw_xnonce2, raw_timestamp, raw_nonce = params
        elif len(params) == 6:
            _rpc_user, job_id, raw_xnonce2, raw_timestamp, raw_nonce, _extra = params
        else:
            raise ValueError(f'expected 5 or 6 params, got {len(params)} instead')
        return cls(
            job_id=job_id,
            nonce=read_uint32(bytearray(bytes.fromhex(raw_nonce)[::-1])),
            xnonce1=xnonce1,
            xnonce2=bytes.fromhex(raw_xnonce2),
            timestamp=read_uint32(bytearray.fromhex(raw_timestamp)[::-1]),
        )

    @property
    def xnonce(self) -> bytes:
        """ Combined xnonce1 and xnonce1
        """
        return self.xnonce1 + self.xnonce2


class SingleMinerJob(NamedTuple):
    """ Partial job unit that is delegated to a miner.
    """

    job_id: str
    prev_hash: bytes
    coinbase_head: bytes
    coinbase_tail: bytes
    merkle_path: tuple[bytes, ...]
    version: int
    bits: bytes  # 4 bytes
    timestamp: int
    hathor_block: HathorBlock
    transactions: list[BitcoinRawTransaction]
    xnonce1: bytes
    xnonce2_size: int
    clean: bool = True
    bitcoin_height: int = 0
    hathor_height: Optional[int] = None

    def to_stratum_params(self) -> list:
        """ Assemble the parameters the way a Stratum client typically expects.
        """
        return [
            self.job_id,
            flip80(self.prev_hash[::-1]).hex(),
            self.coinbase_head.hex(),
            self.coinbase_tail.hex(),
            [i[::-1].hex() for i in self.merkle_path],
            encode_uint32(self.version)[::-1].hex(),
            self.bits.hex(),
            encode_uint32(self.timestamp)[::-1].hex(),  # FIXME/TODO: verify actual endianness
            self.clean
        ]

    def _make_coinbase(self, work: SingleMinerWork) -> BitcoinTransaction:
        """ Assemble the Bitcoin coinbase transaction from this job and a given work.
        """
        return BitcoinTransaction.decode(b''.join([self.coinbase_head, work.xnonce, self.coinbase_tail]))

    def _make_bitcoin_block_and_coinbase(self, work: SingleMinerWork) -> tuple[BitcoinBlockHeader, BitcoinTransaction]:
        """ Assemble the Bitcoin block header and coinbase transaction from this job and a given work.
        """
        coinbase_tx = self._make_coinbase(work)
        bitcoin_header = BitcoinBlockHeader(
            self.version,
            self.prev_hash,
            build_merkle_root_from_path([coinbase_tx.txid] + list(self.merkle_path)),
            work.timestamp or self.timestamp,
            self.bits,
            work.nonce
        )
        return bitcoin_header, coinbase_tx

    def build_bitcoin_block_header(self, work: SingleMinerWork) -> BitcoinBlockHeader:
        """ Build the Bitcoin Block Header from job and work data.
        """
        bitcoin_header, _ = self._make_bitcoin_block_and_coinbase(work)
        return bitcoin_header

    def build_aux_pow(self, work: SingleMinerWork) -> BitcoinAuxPow:
        """ Build the Auxiliary Proof-of-Work from job and work data.
        """
        bitcoin_header, coinbase_tx = self._make_bitcoin_block_and_coinbase(work)
        header = bytes(bitcoin_header)
        header_head, header_tail = header[:36], header[-12:]
        block_base_hash = self.hathor_block.get_mining_base_hash()
        coinbase = bytes(coinbase_tx)
        assert block_base_hash in coinbase
        coinbase_head, coinbase_tail = coinbase.split(block_base_hash)
        return BitcoinAuxPow(header_head, coinbase_head, coinbase_tail, list(self.merkle_path), header_tail)

    def build_bitcoin_block(self, work: SingleMinerWork) -> BitcoinBlock:
        """ Build the Bitcoin Block from job and work data.
        """
        bitcoin_header, coinbase_tx = self._make_bitcoin_block_and_coinbase(work)
        bitcoin_block = BitcoinBlock(bitcoin_header, [coinbase_tx.to_raw()] + self.transactions[:])
        return bitcoin_block

    def dummy_work(self) -> SingleMinerWork:
        """ Used for debugging and validating a block proposal.
        """
        return SingleMinerWork(self.job_id, 0, self.xnonce1, b'\0' * self.xnonce2_size)

    def dummy_bitcoin_block(self) -> BitcoinBlock:
        """ Used for debugging and validating a block proposal.
        """
        return self.build_bitcoin_block(self.dummy_work())


class MergedMiningStratumProtocol(asyncio.Protocol):
    """
    Asyncio protocol that implements server side of the merged mining coordinator.
    """

    DEFAULT_XNONCE2_SIZE = 8  # size in bytes to reserve for extra nonce 2 (which is concatenated with extra nonce 1)
    ESTIMATOR_LOOP_INTERVAL = 30  # in seconds, "frequency" that the function that updates the estimator will be called
    ESTIMATOR_WINDOW_INTERVAL = 60 * 15  # in seconds, size of the window to use for estimating miner's hashrate
    MIN_DIFFICULTY = 128  # minimum "bitcoin difficulty" to assign to jobs
    MAX_DIFFICULTY = 2**208  # maximum "bitcoin difficulty" to assign to jobs
    INITIAL_DIFFICULTY = 8192  # initial "bitcoin difficulty" to assign to jobs, can raise or drop based on solvetimes
    TARGET_JOB_TIME = 15  # in seconds, adjust difficulty so jobs take this long
    MAX_JOBS = 150  # maximum number of jobs to keep in memory

    merged_job: 'MergedJob'

    def __init__(self, coordinator: 'MergedMiningCoordinator', xnonce1: bytes = b'',
                 min_difficulty: Optional[int] = None,
                 job_id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count()):
        self.log = logger.new()
        self.coordinator = coordinator

        self.current_job = None
        self.jobs: MaxSizeOrderedDict = MaxSizeOrderedDict(max=self.MAX_JOBS)
        self.miner_id: Optional[str] = None
        self.miner_address: Optional[bytes] = None
        self.min_difficulty = min_difficulty if min_difficulty is not None else self.MIN_DIFFICULTY
        self.initial_difficulty = PDiff(self.INITIAL_DIFFICULTY)
        self._current_difficulty = PDiff(1)
        self.payback_script_bitcoin: Optional[bytes] = None
        self.payback_script_hathor: Optional[bytes] = None
        self.worker_name: Optional[str] = None
        self.login: Optional[str] = None
        # used to estimate the miner's hashrate, items are a tuple (timestamp, logwork)
        self._submitted_work: list[tuple[float, Weight, Hash]] = []
        self._new_submitted_work: list[tuple[float, Weight, Hash]] = []
        self.last_reduce = 0.0
        self._estimator_last_len = 0
        self.hashrate_ths: Optional[float] = None
        self.user_agent = ''

        self.xnonce1 = xnonce1
        self.xnonce2_size = self.DEFAULT_XNONCE2_SIZE

        self._iter_job_id = job_id_generator() if job_id_generator else None
        self._subscribed = False
        self._authorized = False

        self.estimator_task: Optional[Periodic] = None
        self.buffer = bytearray()

        self.subscribed_at = 0.0
        self.last_submit_at = 0.0

    @property
    def subscribed(self) -> bool:
        return self._subscribed and self._authorized

    @property
    def uptime(self) -> float:
        """ Live uptime calculated from time.time() and self.started_at.
        """
        if not self.subscribed_at:
            return 0.0
        return time.time() - self.subscribed_at

    def status(self) -> dict[Any, Any]:
        """ Build status dict with useful metrics for use in MM Status API.
        """
        return {
            'id': self.miner_id,
            'hashrate_ths': self.hashrate_ths,
            'user_agent': self.user_agent,
            'worker': self.login,
            'worker_name': self.worker_name,
            'xnonce1_hex': self.xnonce1.hex(),
            'xnonce2_size': self.xnonce2_size,
            'subscribed_at': self.subscribed_at or None,
            'last_submit_at': self.last_submit_at or None,
            'uptime': self.uptime,
            'diff': self._current_difficulty,
        }

    def next_job_id(self):
        """ Every call will return a new sequential id for use in job.id.
        """
        if self._iter_job_id:
            return str(next(self._iter_job_id))
        return str(uuid4())

    def connection_made(self, transport):
        # https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseProtocol.connection_made
        self.transport = transport
        self.miner_id = str(uuid4())
        self.coordinator.miner_protocols[self.miner_id] = self
        self.log = self.log.bind(miner_id=self.miner_id)
        self.log.debug('connection made')

    def connection_lost(self, exc):
        # https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseProtocol.connection_lost
        self.log.debug('connection lost', exc=exc)
        if self._subscribed:
            self.log.info('miner disconnected')
        assert self.miner_id is not None
        self.coordinator.miner_protocols.pop(self.miner_id)
        if self.estimator_task:
            asyncio.ensure_future(self.estimator_task.stop())

    def start_estimator(self) -> None:
        """ Start periodic estimator task."""
        if self.estimator_task is None:
            self.last_reduced = time.time()
            self.estimator_task = Periodic(self.estimator_loop, self.ESTIMATOR_LOOP_INTERVAL)
            asyncio.ensure_future(self.estimator_task.start())

    def data_received(self, data):
        """ Parse data, buffer/assemble and split lines, pass lines to `line_received`.
        """
        self.buffer.extend(data)
        while self.buffer.find(b'\n') >= 0:
            line, _, self.buffer = self.buffer.partition(b'\n')
            try:
                self.line_received(bytes(line))
            except Exception:
                self.log.exception('failed to process message, aborting')
                self.transport.close()

    def line_received(self, message: bytes) -> None:
        """ Parse line, pass result to `json_received`.
        """
        from json import JSONDecodeError

        from hathor.util import json_loadb

        self.log.debug('line received', line=message)
        try:
            data = json_loadb(message)
        except JSONDecodeError:
            self.log.warn('invalid message received', message=message, message_hex=message.hex(), exc_info=True)
            return self.send_error(PARSE_ERROR, data={'message': message})
        assert isinstance(data, dict)
        self.json_received(data)

    def json_received(self, data: dict[Any, Any]) -> None:
        """ Process JSON and forward to the appropriate handle, usually `handle_request`.
        """
        msgid = data.get('id')
        if 'method' in data:
            return self.handle_request(data['method'], data.get('params'), msgid)
        elif 'result' in data and 'error' in data:
            if data['result'] and data['error'] is None:
                return self.handle_result(data['result'], msgid)
            elif data['error'] and data['result'] is None:
                return self.handle_error(data['error'], data.get('data'), msgid)
        elif 'result' in data:
            return self.handle_result(data['result'], msgid)
        elif 'error' in data:
            return self.handle_error(data['error'], data.get('data'), msgid)
        return self.send_error(
            INVALID_REQUEST, data={
                'message': data,
                'error': 'Could not identify message as request, result or error.'
            })

    def send_request(self, method: str, params: Union[None, list, dict], msgid: Union[str, int, None] = None) -> None:
        """ Sends a JSON-RPC 2.0 request.
        """
        data: dict[str, Any] = {'method': method, 'params': params}
        # XXX: keeping the same msgid type the client sent
        data['id'] = msgid
        self.log.debug('send request', data=data)
        self.send_json(data)

    def send_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Sends a JSON-RPC 2.0 result.
        """
        data = {'result': result, 'error': None}
        if msgid is not None:
            data['id'] = msgid
        self.log.debug('send result', data=data)
        return self.send_json(data)

    def send_error(self, error: dict, msgid: Optional[str] = None, data: Any = None) -> None:
        """ Sends a JSON-RPC 2.0 error.
        """
        message = {'error': error, 'data': data}
        if msgid is not None:
            message['id'] = msgid
        self.log.info('send error', data=message)
        self.send_json(message)

        # Lose connection in case of any native JSON RPC error
        if error['code'] <= UNRECOVERABLE_ERROR_CODE_MAX and self.transport is not None:
            self.transport.close()

    def send_json(self, json: dict) -> None:
        """ Encodes a JSON and send it through the LineReceiver interface.
        """
        from hathor.util import json_dumpb
        try:
            message = json_dumpb(json)
            self.log.debug('send line', line=message)
            self.transport.write(message + b'\n')
        except TypeError:
            self.log.error('failed to encode', json=json)

    def handle_request(self, method: str, params: Optional[Union[list, dict]], msgid: Optional[str]) -> None:
        """ Handles subscribe and submit requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[list, dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('handle request', method=method, params=params)

        if method in {'subscribe', 'mining.subscribe', 'login'}:
            assert isinstance(params, list)
            return self.handle_subscribe(params, msgid)
        if method in {'authorize', 'mining.authorize'}:
            assert isinstance(params, list)
            return self.handle_authorize(params, msgid)
        if method in {'submit', 'mining.submit'}:
            assert isinstance(params, list)
            return self.handle_submit(params, msgid)
        if method in {'configure', 'mining.configure'}:
            assert isinstance(params, list)
            return self.handle_configure(params, msgid)
        if method in {'multi_version', 'mining.multi_version'}:
            assert isinstance(params, list)
            return self.handle_multi_version(params, msgid)
        if method == 'mining.extranonce.subscribe':
            return self.handle_extranonce_subscribe(msgid)

        self.send_error(METHOD_NOT_FOUND, msgid, data={'method': method, 'supported_methods': ['submit', 'subscribe']})

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any.
        """
        self.log.debug('handle result', msgid=msgid, result=result)

    def handle_error(self, error: dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any errors since there are not supposed to be any.
        """
        self.log.error('handle error', msgid=msgid, error=error)

    def handle_authorize(self, params: list, msgid: Optional[str]) -> None:
        """ Handles authorize request by always authorizing even if the request is invalid.
        """
        if self.coordinator.address_from_login:
            try:
                login, password = params
                self.payback_script_hathor, self.payback_script_bitcoin, self.worker_name = \
                    parse_login_with_addresses(login)
                if self.worker_name:
                    self.log = self.log.bind(worker_name=self.worker_name)
            except Exception as e:
                self.log.warn('authorization failed', exc=e, login=login, password=password)
                # TODO: proper error
                self.send_error({'code': 0, 'message': 'Address should be of the format <HTR_ADDR>.<BTC_ADDR>'}, msgid)
                self.transport.close()
                return
            if 'nicehash' in password.lower():
                self.log.info('special case mindiff for NiceHash')
                self.min_difficulty = NICEHASH_MIN_DIFF
            self.send_result(True, msgid)
        else:
            # TODO: authorization system
            login, _password = params
            self.send_result(True, msgid)
        if self._subscribed:
            self.set_difficulty(self.initial_difficulty)
        self.login = login
        self._authorized = True
        self.log.info('miner authorized')
        self.job_request()
        self.start_estimator()

    def handle_configure(self, params: list, msgid: Optional[str]) -> None:
        """ Handles stratum-extensions configuration

        See: https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki
        """
        self.log.debug('handle configure', msgid=msgid, params=params)
        exts, exts_params = params
        res = {ext: False for ext in exts}

        if 'minimum-difficulty' in exts:
            self.min_difficulty = int(exts_params['minimum-difficulty.value'])
            res['minimum-difficulty'] = True

        self.send_result(res, msgid)

    def handle_subscribe(self, params: list[str], msgid: Optional[str]) -> None:
        """ Handles subscribe request by answering it and triggering a job request.

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        from math import log2
        assert self.miner_id is not None
        self._subscribed = True
        self.subscribed_at = time.time()
        self.log.info('miner subscribed', address=self.miner_address, params=params)
        # session = str(self.miner_id)
        session = [['mining.set_difficulty', '1'], ['mining.notify', str(self.miner_id)]]
        self.send_result([session, self.xnonce1.hex(), self.xnonce2_size], msgid)
        self.user_agent = params[0]
        if 'nicehash' in self.user_agent.lower():
            self.log.info('special case mindiff for NiceHash')
            self.initial_difficulty = PDiff(NICEHASH_MIN_DIFF)
            self.min_difficulty = NICEHASH_MIN_DIFF
        if '/' in self.user_agent:
            try:
                # example: bmminer/2.0.0/Antminer S9j/14500
                # the last part will often contain an indication of the hashrate (in GH/s)
                hashrate_ghs = int(self.user_agent.split('/')[-1])
                self.log.debug('detected hashrate', hashrate_ghs=hashrate_ghs)
            except ValueError:
                pass
            else:
                self.initial_difficulty = Weight(log2(hashrate_ghs * self.TARGET_JOB_TIME) + log2(1e9)).to_pdiff()
        if self._authorized:
            self.set_difficulty(self.initial_difficulty)

    def handle_multi_version(self, params: list[Any], msgid: Optional[str]) -> None:
        """ Handles multi_version requests
        """
        self.send_result(True, msgid)

    def handle_extranonce_subscribe(self, msgid: Optional[str]) -> None:
        """ Handles extranonce.subscribe request, already assumed true
        """
        self.send_result(True, msgid)

    def handle_submit(self, params: list[Any], msgid: Optional[str]) -> None:
        """ Handles submit request by validating and propagating the result

        - params: rpc_user, job_id, xnonce2, time, nonce

        Example:

        - ['', '6a16cffa-47c0-41d9-b92f-44e05d3c25dd', '0000000000000000', 'c359f65c', '47c8f488']
        """
        from itertools import chain

        self.log.debug('handle submit', msgid=msgid, params=params)

        work = SingleMinerWork.from_stratum_params(self.xnonce1, params)

        job = self.jobs.get(work.job_id)
        if not job:
            self.log.error('job not found', job_id=work.job_id)
            self.send_error(JOB_NOT_FOUND, data={'message': 'Job not found.'})
            return
        self.last_submit_at = time.time()

        bitcoin_block_header = job.build_bitcoin_block_header(work)
        block_base_hash = job.hathor_block.get_mining_base_hash()
        block_hash = Hash(bitcoin_block_header.hash)
        self.log.debug('work received', bitcoin_header=bytes(bitcoin_block_header).hex(),
                       hathor_block=job.hathor_block, block_base_hash=block_base_hash.hex(),
                       hash=block_hash)

        try:
            aux_pow = job.build_aux_pow(work)
            aux_pow.verify_magic_number(block_base_hash)
        except TxValidationError as e:
            self.log.warn('invalid work', job_id=work.job_id, error=e)
            self.send_error(INVALID_SOLUTION, data={'message': 'Job has invalid work.'})
            return

        submitted_hashes = set(h for _, __, h, in chain(self._submitted_work, self._new_submitted_work))
        if block_hash in submitted_hashes:
            self.log.warn('invalid work', job_id=work.job_id)
            self.send_error(DUPLICATE_SOLUTION)
            return

        # Share accepted
        self.send_result(True, msgid)

        now = time.time()
        luck_logwork = block_hash.to_weight()
        diff_logwork = self._current_difficulty.to_weight()
        logwork = min(luck_logwork, diff_logwork)
        self._new_submitted_work.append((now, logwork, block_hash))

        # too many jobs too fast, increase difficulty out of caution (more than 10 submits within the last 10s)
        if sum(1 for t, w, _ in self._new_submitted_work if now - t < 10) > 10:
            self._submitted_work.extend(self._new_submitted_work)
            self._new_submitted_work = []
            self.set_difficulty(self._current_difficulty * 2)
            return

        self.log.debug('forward work to hathor', aux_pow=aux_pow)
        asyncio.ensure_future(self.submit_to_hathor(job, aux_pow))

        self.log.debug('forward work to bitcoin', work=work)
        asyncio.ensure_future(self.submit_to_bitcoin(job, work))

    async def submit_to_hathor(self, job: SingleMinerJob, aux_pow: BitcoinAuxPow) -> None:
        """ Submit AuxPOW to Hathor stratum.
        """
        block = job.hathor_block
        block.aux_pow = aux_pow
        block.update_hash()
        block_hash = Hash(block.hash)
        if block_hash.to_weight() < block.weight:
            self.log.debug('high hash for Hathor, keep mining')
            return
        if job.hathor_height is not None:
            if self.coordinator.should_skip_hathor_submit(job.hathor_height):
                self.log.debug('share is too late, skip Hathor submit')
                return
        try:
            assert self.coordinator.hathor_mining is not None
            res = await self.coordinator.hathor_mining.submit(block)
        except Exception:
            self.log.warn('submit to Hathor failed', exc_info=True)
            return
        self.log.debug('hathor_mining.submit', res=res)
        if job.hathor_height is not None:
            self.coordinator.update_hathor_submitted(job.hathor_height)
        if res:
            self.log.info('new Hathor block found!!!', hash=block.hash.hex())

    async def submit_to_bitcoin(self, job: SingleMinerJob, work: SingleMinerWork) -> None:
        """ Submit work to Bitcoin RPC.
        """
        bitcoin_rpc = self.coordinator.bitcoin_rpc
        if bitcoin_rpc is None:
            return
        # bitcoin_block = job.build_bitcoin_block(work)  # XXX: too expensive for now
        bitcoin_block_header = job.build_bitcoin_block_header(work)
        block_hash = Hash(bitcoin_block_header.hash)
        block_target = Target(int.from_bytes(bitcoin_block_header.bits, 'big'))
        if block_hash.to_u256() > block_target.to_u256():
            self.log.debug('high hash for Bitcoin, keep mining')
            return
        if self.coordinator.should_skip_bitcoin_submit(job.bitcoin_height):
            self.log.debug('late winning share, skipping Bitcoin submit')
            return
        bitcoin_block = job.build_bitcoin_block(work)  # XXX: far fewer cases, so it's OK now
        data = bytes(bitcoin_block)
        try:
            res = await bitcoin_rpc.submit_block(data)
        except Exception:
            self.log.warn('submit to Bitcoin failed', exc_info=True)
            return
        self.coordinator.update_bitcoin_submitted(job.bitcoin_height)
        self.log.debug('bitcoin_rpc.submit_block', res=res)
        if res is None:
            self.log.info('new Bitcoin block found!!!', hash=bitcoin_block.header.hash.hex())
            await self.coordinator.update_bitcoin_block()
        else:
            # Known reasons:
            # - high-hash: PoW not enough, shouldn't happen because we check the difficulty before sending
            # - bad-*: invalid block data
            # - unexpected-witness: transaction has inputs with witness but isn't marked as containing witnesses
            self.log.error('block rejected from Bitcoin', reason=res)

    def set_difficulty(self, diff: float) -> None:
        """ Sends the difficulty to the connected client, applies for all future "mining.notify" until it is set again.
        """
        old_diff = int(self._current_difficulty)
        self._current_difficulty = PDiff(max(self.min_difficulty, diff))
        new_diff = int(self._current_difficulty)
        if new_diff != old_diff:
            self.send_request('mining.set_difficulty', [new_diff])
            self.log.info('update difficulty', diff=new_diff)

    def job_request(self) -> None:
        """ Sends a job request to the connected client.
        """
        if not self.coordinator.merged_job:
            self.send_error(NODE_SYNCING, data={'message': 'Not ready to give a job.'})
            return

        try:
            job = self.coordinator.merged_job.new_single_miner_job(self)
        except (ValueError, ScriptError) as e:
            # ScriptError might happen if try to use a mainnet address in the testnet or vice versa
            # ValueError happens if address is not a valid base58 address
            self.send_error(INVALID_PARAMS, data={'message': str(e)})
        else:
            self.jobs[job.job_id] = job

            self.send_request('mining.notify', job.to_stratum_params())

            # for debugging only:
            bitcoin_block = job.build_bitcoin_block_header(job.dummy_work())
            self.log.debug('job updated', bitcoin_block=bytes(bitcoin_block).hex(),
                           merkle_root=bitcoin_block.merkle_root.hex())

    async def estimator_loop(self) -> None:
        """ This loop only cares about reducing the current difficulty if the miner takes too long to submit a solution
        """
        from functools import reduce
        from math import log2
        if not self.coordinator.merged_job:
            # not ready yet, skip this run
            return
        now = time.time()
        # remove old entries
        self._submitted_work = [i for i in self._submitted_work if now - i[0] < self.ESTIMATOR_WINDOW_INTERVAL]
        # too little jobs, reduce difficulty
        if len(self._new_submitted_work) == 0 and len(self._submitted_work) == 0 and now - self.last_reduce > 60:
            self.last_reduce = now
            self.set_difficulty(self._current_difficulty / 2)
            return
        # add new entries
        self._submitted_work.extend(self._new_submitted_work)
        self._new_submitted_work = []
        # otherwise, estimate the hashrate, and aim for a difficulty that approximates the target job time
        # window size
        if not self._submitted_work:
            return
        delta = now - min(t for (t, _, __) in self._submitted_work)
        # total logwork (considering the highest hash only)
        logwork = Weight(reduce(lambda w1, w2: w1.logsum(w2), (w for (_, w, __) in self._submitted_work)))
        # calculate hashrate in TH/s
        self.hashrate_ths = 2**(logwork - log2(delta) - log2(1e12))
        target_diff = Weight(logwork - log2(delta) + log2(self.TARGET_JOB_TIME)).to_pdiff()
        self.set_difficulty(target_diff)


class BitcoinCoordJob(NamedTuple):
    version: int
    previous_block_hash: bytes
    coinbase_value: int
    target: bytes  # FIXME: I think it should be int or float
    min_time: int
    # nonce_range: int
    size_limit: int
    bits: bytes
    height: int
    transactions: list[BitcoinRawTransaction]
    merkle_path: tuple[bytes, ...]
    witness_commitment: Optional[bytes] = None
    append_to_input: bool = True

    @classmethod
    def create_dummy(cls, merkle_path_len: int = 0) -> 'BitcoinCoordJob':
        """ Creates a dummy instance with zeroed values and optionally a merkle path with the given length.
        """
        if merkle_path_len > 0:
            transactions = [BitcoinRawTransaction(ZEROED_32, ZEROED_32, b'')] * (2 ** merkle_path_len - 1)
            merkle_path = tuple(build_merkle_path_for_coinbase([t.txid for t in transactions]))
        else:
            transactions = []
            merkle_path = tuple()
        return cls(
            version=0,
            previous_block_hash=ZEROED_32,
            coinbase_value=0,
            target=ZEROED_32,
            min_time=0,
            size_limit=0,
            bits=ZEROED_4,
            height=0,
            transactions=transactions,
            merkle_path=merkle_path,
        )

    @classmethod
    def from_dict(cls, params: dict) -> 'BitcoinCoordJob':
        r""" Convert from dict of the properties returned from Bitcoin RPC.

        Examples:

        >>> BitcoinCoordJob.from_dict({
        ...     'version': 536870912,
        ...     'previousblockhash': '000000000000006b18c93038f4bc41d3b58f4f205d1ebf0a532b2c8de61ce814',
        ...     'coinbasevalue': 41235653,
        ...     'target': '000000000000013e450000000000000000000000000000000000000000000000',
        ...     'mintime': 1559301551,
        ...     'noncerange': '00000000ffffffff',
        ...     'sizelimit': 4000000,
        ...     'bits': '1a013e45',
        ...     'height': 1518604,
        ...     'transactions': [
        ...         {
        ...             'data': '0100000002fa0bae9c4bc4cdbba7533aee52ce0a2c50d51ec026abf4e11e7a265'
        ...                     '92a95aef8000000006b4830450221008b9e7b9ba01826f1ebfa3301d06954dcd6'
        ...                     'f4826295cb6b898c0e3706929a089b0220220fd1e1bf3b4dc1d175e35759c7761'
        ...                     '79f7bd697c559071e631aebbbc7f3bf3f012103d06840fd042383b504d910d20a'
        ...                     '505845713873b24b9966dbd60acf748bc833e9ffffffff387560a936334e182a3'
        ...                     '0226dca6aabbfab7c7b7b30d7848e9051a29e7757f88c000000006a4730440220'
        ...                     '4059e61d73482ce3da378349b74f87592932a8ab2e052643ce17eb2752e46b5e0'
        ...                     '2204cc766bcd07052d4e78bb9b703d3e42abc155f0d1f7f028bed74ebf2d5d361'
        ...                     '8d012103d06840fd042383b504d910d20a505845713873b24b9966dbd60acf748'
        ...                     'bc833e9ffffffff0240420f000000000017a914fc57aaf5ec84dd472205e568a6'
        ...                     '0984f52c654a6f87c0d40100000000001976a914f12f2c6e408b3cdff1991b878'
        ...                     '3d1eb428f57814b88ac00000000',
        ...             'txid': 'bbde19e3d56e01f9a7e46dcbff218a58a518a5e5f089197d1039f11db48e3d51',
        ...             'hash': 'bbde19e3d56e01f9a7e46dcbff218a58a518a5e5f089197d1039f11db48e3d51',
        ...             'depends': [],
        ...             'fee': 80000,
        ...             'sigops': 4,
        ...             'weight': 1484
        ...         },
        ...         {
        ...             'data': '0100000001513d8eb41df139107d1989f0e5a518a5588a21ffcb6de4a7f9016ed'
        ...                     '5e319debb00000000fdfd000047304402207f78c43d18263ba6ce13a4876eebaa'
        ...                     'd04366ca8f0b61b9b7c9caa9150ff907f802205bf0a2612469c960471e71e5dda'
        ...                     'f952b4e6e567a3001acaf68bd2cba30e6be4301483045022100d1da2de3a49dea'
        ...                     '091217017c8d20fc2f4be3b2300312141f824e73ddbd5b2dd802201eabe0bd116'
        ...                     '42c76881785497e0ebf05c63acd4b97b5e35b999ff4d9f5d7194a014c69522103'
        ...                     '10145f5e24c12a5967e8a0794e183398082ba26724b2cfa3db35fe6a1598eacd2'
        ...                     '103a35bcdd61bc5e2d59b48fe04c26a9aabcbedc03b8805409a06af8099c1f48a'
        ...                     'db2103a38489db89bf9c36e3706470af4e5adcd28171d12bbae0c53743dc435bf'
        ...                     '578ab53aeffffffff0120a10700000000001976a914f12f2c6e408b3cdff1991b'
        ...                     '8783d1eb428f57814b88ac00000000',
        ...             'txid': '59a536a8cf75db6f669cc2b7b6561feafaa772f96026a5358a6b94ed701e8612',
        ...             'hash': '59a536a8cf75db6f669cc2b7b6561feafaa772f96026a5358a6b94ed701e8612',
        ...             'depends': [1],
        ...             'fee': 500000,
        ...             'sigops': 16,
        ...             'weight': 1360
        ...         },
        ...         {
        ...             'data': '01000000000104a4b446dbe87373dcfb0bf4c07e96de9fd78ae7768f49abfdad2'
        ...                     '71660de4ddc300a00000000ffffffffa4b446dbe87373dcfb0bf4c07e96de9fd7'
        ...                     '8ae7768f49abfdad271660de4ddc300c00000000ffffffffa4b446dbe87373dcf'
        ...                     'b0bf4c07e96de9fd78ae7768f49abfdad271660de4ddc300d00000000ffffffff'
        ...                     'a4b446dbe87373dcfb0bf4c07e96de9fd78ae7768f49abfdad271660de4ddc301'
        ...                     '400000000ffffffff0177080a000000000017a914bb77f4e0bf4e97597446d3f1'
        ...                     '25c516f1e665096f870400473044022027a8532865a6812ad6bf045225237f811'
        ...                     '50e612480a96223f10612bc42109b78022011a96004050dd4a880645dd53f4e3c'
        ...                     '25d8f03ec674f6365a0ee772e0bef17f0f01473044022031161d3e6a6e67f251a'
        ...                     'a27d8b3dde1141e3fad2b237b3f150b5f036c42fdd0d102203b078466422e8b3f'
        ...                     'f968bbbe43a6003c51094491374a2acd5898c41018bc20f40169522103b153116'
        ...                     '2cd4d4caafa9d0353ca15a6ac34fa2b114fd6d8289bbb620098e50aa7210249a4'
        ...                     'e1712090d624d147fba494d50478f1083e922f4e021d437a6bc4f1b8057e21022'
        ...                     '2b2b4d2b40fd1d512ac647f5498b10fc6b1395247c94f916d24a207365393fc53'
        ...                     'ae0400483045022100a2f72f07dadad031198ccc6d3d8756ef99ec15ea57a1654'
        ...                     '75daaed0c6664b2f702200ac9a3135407b7c454a91e4b9097a3cdeb0518a1875c'
        ...                     '55bf1cf3a80f62c8a66d0147304402206706cd936ce92168c411214bb0e049c24'
        ...                     '608354d97e23a57e56dff2a72dd170e02204bb6f6b0899edc74644d29354ea47e'
        ...                     'a197a9de3b038dde6e2cf5394cd8a89ef20169522103b1531162cd4d4caafa9d0'
        ...                     '353ca15a6ac34fa2b114fd6d8289bbb620098e50aa7210249a4e1712090d624d1'
        ...                     '47fba494d50478f1083e922f4e021d437a6bc4f1b8057e210222b2b4d2b40fd1d'
        ...                     '512ac647f5498b10fc6b1395247c94f916d24a207365393fc53ae040048304502'
        ...                     '2100b1d78a20d5ac13d6586d4536e7ce6ee8bbd60201c6fa9ba2ccd089dabda38'
        ...                     'f6402203e3509480145c024d33d50877a8c6fbb60bb79438b88f6796bdfde7692'
        ...                     '30a8dd01473044022079d26243a0614b2169715b980c0a1e60847cf9e832679e8'
        ...                     '60eb2e6e35d2d7893022044d92149a3199bfedb902cb84a8ffc7b6200ad31704e'
        ...                     'bf98a33ad26a4dd57fd40169522103b1531162cd4d4caafa9d0353ca15a6ac34f'
        ...                     'a2b114fd6d8289bbb620098e50aa7210249a4e1712090d624d147fba494d50478'
        ...                     'f1083e922f4e021d437a6bc4f1b8057e210222b2b4d2b40fd1d512ac647f5498b'
        ...                     '10fc6b1395247c94f916d24a207365393fc53ae040047304402207ff37811a24c'
        ...                     'c3c8fbeb559990e18dc32f84c5a64286a791d017b6686ae8c0de022011c8ed11c'
        ...                     '2221b13f072ec98c80d097165e173f96b16f601f651bb41be7b50330148304502'
        ...                     '2100e7f07bb34f10125267ba937efd81ee411c05cb39e27b7cf9b92baf7524861'
        ...                     '8fe022051cab5e74063206157d7b68d095b3eca972405bbb83a5115a180f68c65'
        ...                     'c228bd0169522103b1531162cd4d4caafa9d0353ca15a6ac34fa2b114fd6d8289'
        ...                     'bbb620098e50aa7210249a4e1712090d624d147fba494d50478f1083e922f4e02'
        ...                     '1d437a6bc4f1b8057e210222b2b4d2b40fd1d512ac647f5498b10fc6b1395247c'
        ...                     '94f916d24a207365393fc53ae00000000',
        ...             'txid': 'b5c3982dc1315ef713e41c480fc640fedcac22b0fa5fa9042174bf6035846d88',
        ...             'hash': '04455477e44288f707525535758b41a09974339fd49f95b8747ac3fc5ad8a81f',
        ...             'depends': [],
        ...             'fee': 142473,
        ...             'sigops': 12,
        ...             'weight': 1837
        ...         }
        ...     ]
        ... })
        BitcoinCoordJob(...)
        """
        segwit_commitment = params.get('default_witness_commitment')
        return cls(
            params['version'],
            bytes.fromhex(params['previousblockhash']),
            params['coinbasevalue'],
            bytes.fromhex(params['target']),
            params['mintime'],
            params['sizelimit'],
            bytes.fromhex(params['bits']),
            params['height'],
            list(map(BitcoinRawTransaction.from_dict, params['transactions'])),
            tuple(build_merkle_path_for_coinbase([bytes.fromhex(tx['txid']) for tx in params['transactions']])),
            bytes.fromhex(segwit_commitment) if segwit_commitment is not None else None,
        )

    def to_dict(self) -> dict[Any, Any]:
        """ Convert back to a simplified dict format similar to Bitcoin's, used by MM Status API.
        """
        return {
            'version': self.version,
            'previousblockhash': self.previous_block_hash.hex(),
            'coinbasevalue': self.coinbase_value,
            'target': self.target.hex(),
            'mintime': self.min_time,
            'sizelimit': self.size_limit,
            'bits': self.bits.hex(),
            'height': self.height,
            'transactions': [
                {
                    'txid': tx.txid.hex(),
                    'hash': tx.hash.hex(),
                }
                for tx in self.transactions
            ],
            'merkle_path': [h.hex() for h in self.merkle_path],
        }

    def make_coinbase_transaction(self, hathor_block_hash: bytes, payback_script_bitcoin: bytes,
                                  extra_nonce_size: Optional[int] = None) -> BitcoinTransaction:
        """ The coinbase transaction is entirely defined by the coordinator, which acts as a pool server.
        """
        import struct

        inputs = []
        outputs: list[BitcoinTransactionOutput] = []

        # coinbase input
        coinbase_script = encode_bytearray(struct.pack('<q', self.height).rstrip(b'\0'))

        if self.append_to_input:
            coinbase_script += MAGIC_NUMBER
            coinbase_script += hathor_block_hash
            if extra_nonce_size is not None:
                coinbase_script += b'\0' * extra_nonce_size

        coinbase_input = BitcoinTransactionInput.coinbase(coinbase_script)
        # append after sorting out segwit

        # coinbase output: payout
        coinbase_output = BitcoinTransactionOutput(self.coinbase_value, payback_script_bitcoin)
        outputs.append(coinbase_output)

        if self.witness_commitment is not None:
            segwit_output = BitcoinTransactionOutput(0, self.witness_commitment)
            outputs.append(segwit_output)
            coinbase_input.script_witness.append(ZEROED_32)

        # append now because segwit presence may change this
        inputs.append(coinbase_input)

        # add hathor base block hash to coinbase:
        if not self.append_to_input:
            output_script = MAGIC_NUMBER
            output_script += hathor_block_hash
            if extra_nonce_size is not None:
                output_script += b'\0' * extra_nonce_size

            coinbase_output = BitcoinTransactionOutput(0, output_script)
            outputs.append(coinbase_output)

        return BitcoinTransaction(inputs=inputs, outputs=outputs, include_witness=False)

    def get_timestamp(self) -> int:
        """ Timestamp is now or min_time, whatever is higher."""
        from datetime import datetime
        return max(int(datetime.now().timestamp()), self.min_time)


class MergedJob(NamedTuple):
    """ Current merged job, of which 'single miner jobs' may fullfill the work for either coin.
    """

    hathor_coord: HathorCoordJob
    bitcoin_coord: BitcoinCoordJob
    payback_script_bitcoin: Optional[bytes]
    clean: bool

    def build_sample_block_proposal(self) -> BitcoinBlock:
        return self._new_single_miner_job(
            '',
            b'\0' * MergedMiningCoordinator.XNONCE1_SIZE,
            MergedMiningStratumProtocol.DEFAULT_XNONCE2_SIZE,
            b'',
            b'',
        ).dummy_bitcoin_block()

    def new_single_miner_job(self, protocol: MergedMiningStratumProtocol) -> SingleMinerJob:
        """ Generate a partial job for a single miner, based on this job.
        """
        assert protocol.payback_script_hathor is not None
        payback_script_bitcoin = self.payback_script_bitcoin or protocol.payback_script_bitcoin
        assert payback_script_bitcoin is not None
        return self._new_single_miner_job(
            protocol.next_job_id(),
            protocol.xnonce1,
            protocol.xnonce2_size,
            protocol.payback_script_hathor,
            payback_script_bitcoin,
        )

    def _new_single_miner_job(self, job_id: str, xnonce1: bytes, xnonce2_size: int, payback_script_hathor: bytes,
                              payback_script_bitcoin: bytes) -> SingleMinerJob:
        """ Private method, used on `build_sample_block_proposal` and `new_single_miner_job`.
        """
        xnonce_size = len(xnonce1) + xnonce2_size

        # base txs for merkle tree, before coinbase
        transactions = self.bitcoin_coord.transactions

        # payback_address_hathor
        hathor_block = self.hathor_coord.block.clone()
        assert isinstance(hathor_block, HathorBlock)
        if not hathor_block.outputs[0].script:
            hathor_block.outputs[0].script = payback_script_hathor
            hathor_block.update_hash()

        # build coinbase transaction with hathor block hash
        hathor_block_hash = hathor_block.get_mining_base_hash()
        coinbase_tx = self.bitcoin_coord.make_coinbase_transaction(
            hathor_block_hash,
            payback_script_bitcoin,
            xnonce_size,
        )
        coinbase_bytes = bytes(coinbase_tx)
        coinbase_head, coinbase_tail = coinbase_bytes.split(hathor_block_hash + b'\0' * xnonce_size, 1)
        coinbase_head += hathor_block_hash
        assert len(coinbase_bytes) == len(coinbase_head) + xnonce_size + len(coinbase_tail)  # just a sanity check

        logger.debug('created miner job with scripts',
                     htr_script=hathor_block.outputs[0].script.hex(),
                     btc_script=payback_script_bitcoin.hex())

        # TODO: check if total transaction size increase exceed size and sigop limits, there's probably an RPC for this

        return SingleMinerJob(
            job_id=job_id,
            prev_hash=self.bitcoin_coord.previous_block_hash,
            coinbase_head=coinbase_head,
            coinbase_tail=coinbase_tail,
            merkle_path=self.bitcoin_coord.merkle_path,
            version=self.bitcoin_coord.version,
            bits=self.bitcoin_coord.bits,
            hathor_block=hathor_block,
            timestamp=self.bitcoin_coord.get_timestamp(),
            transactions=transactions,
            clean=self.clean,
            bitcoin_height=self.bitcoin_coord.height,
            hathor_height=self.hathor_coord.height,
            xnonce1=xnonce1,
            xnonce2_size=xnonce2_size,
        )


def strip_transactions(data: dict, rm_cond: Callable[[dict], bool]) -> None:
    """ Remove all transactions from gbt data for which rm_cond returns True. """
    selected_txs = []
    excluded_txs = []
    for t in data['transactions']:
        if rm_cond(t):
            excluded_txs.append(t)
        else:
            selected_txs.append(t)
    if excluded_txs:
        excluded_fee = sum(t['fee'] for t in excluded_txs)
        data['coinbasevalue'] -= excluded_fee
        data['transactions'] = selected_txs
        logger.warn('{removed} txs removed, {left} left', removed=len(excluded_txs), left=len(selected_txs),
                    removed_fee=excluded_fee)


class MergedMiningCoordinator:
    """
    Asyncio factory server for Hathor Stratum protocols.
    Interfaces with fullnode to keep mining jobs up to date and to submit successful ones.

    xnonce1: set by the server, used to prevent miners work from overlapping
    xnonce2: set by the client, server only sets the size (defaults to 8 bytes), bigger search space
    """

    BITCOIN_UPDATE_INTERVAL = 10.0
    # very arbitrary, max times since last submit that we consider sending a new winning share
    BITCOIN_MAX_FUTURE_SUBMIT_SECONDS = 30.0
    HATHOR_MAX_FUTURE_SUBMIT_SECONDS = 30.0
    XNONCE1_SIZE = 2
    MAX_XNONCE1 = 2**XNONCE1_SIZE - 1
    MAX_RECONNECT_BACKOFF = 30

    def __init__(self,
                 bitcoin_rpc: IBitcoinRPC | None,
                 hathor_client: IHathorClient,
                 payback_address_bitcoin: str | None,
                 payback_address_hathor: str | None,
                 address_from_login: bool = True,
                 min_difficulty: int | None = None,
                 sequential_xnonce1: bool = False,
                 rng: Random | None = None,
                 dummy_merkle_path_len: int | None = None,
                 ):
        self.log = logger.new()
        if rng is None:
            rng = Random()
        self.rng = rng
        self.bitcoin_rpc = bitcoin_rpc
        self.hathor_client = hathor_client
        self.hathor_mining: Optional[IMiningChannel] = None
        self.address_from_login = address_from_login
        self.jobs: set[SingleMinerJob] = set()
        self.miner_protocols: dict[str, MergedMiningStratumProtocol] = {}
        self.payback_address_bitcoin: Optional[str] = payback_address_bitcoin
        self.payback_address_hathor: Optional[str] = payback_address_hathor
        self.bitcoin_coord_job: Optional[BitcoinCoordJob] = None
        self.hathor_coord_job: Optional[HathorCoordJob] = None
        self.last_bitcoin_block_received = 0.0
        self.last_bitcoin_height_submitted = 0
        self.last_bitcoin_timestamp_submitted = 0.0
        self.last_hathor_block_received = 0.0
        self.last_hathor_height_submitted = 0
        self.last_hathor_timestamp_submitted = 0.0
        self.merged_job: Optional[MergedJob] = None
        self.min_difficulty = min_difficulty
        self.sequential_xnonce1 = sequential_xnonce1
        self._next_xnonce1 = 0
        self.job_count = 0
        self.update_bitcoin_block_task: Optional[asyncio.Task] = None
        self.update_hathor_block_task: Optional[asyncio.Task] = None
        self.started_at = 0.0
        self.strip_all_transactions = False
        self.strip_segwit_transactions = False
        self.dummy_merkle_path_len = dummy_merkle_path_len or 0

    @property
    def uptime(self) -> float:
        """ Live uptime calculated from time.time() and self.started_at.
        """
        if not self.started_at:
            return 0.0
        return time.time() - self.started_at

    def next_xnonce1(self) -> bytes:
        """ Generate the next xnonce1, for keeping each subscription with a different xnonce1.
        """
        if self.sequential_xnonce1:
            xnonce1 = self._next_xnonce1
            self._next_xnonce1 += 1
            if self._next_xnonce1 > self.MAX_XNONCE1:
                self._next_xnonce1 = 0
            return xnonce1.to_bytes(self.XNONCE1_SIZE, 'big')
        else:
            return self.rng.randbytes(self.XNONCE1_SIZE)

    def __call__(self) -> MergedMiningStratumProtocol:
        """ Making this class a callable so it can be used as a protocol factory.

        See: https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_server
        """
        return MergedMiningStratumProtocol(self, self.next_xnonce1(), min_difficulty=self.min_difficulty)

    def update_jobs(self) -> None:
        """ Creates and sends a new job for each subscribed miner.
        """
        self.merged_job = self.next_merged_job
        for miner, protocol in self.miner_protocols.items():
            if protocol.subscribed:
                protocol.job_request()

    async def start(self) -> None:
        """ Starts the coordinator and subscribes for new blocks on the both networks in order to update miner jobs.
        """
        loop = asyncio.get_event_loop()
        self.started_at = time.time()
        if self.bitcoin_rpc is not None:
            self.update_bitcoin_block_task = loop.create_task(self.update_bitcoin_block())
        else:
            self.bitcoin_coord_job = BitcoinCoordJob.create_dummy(self.dummy_merkle_path_len)
        self.update_hathor_block_task = loop.create_task(self.update_hathor_block())

    async def stop(self) -> None:
        """ Stops the client, interrupting mining processes, stoping supervisor loop, and sending finished jobs.
        """
        finals = []
        if self.update_bitcoin_block_task is not None:
            self.update_bitcoin_block_task.cancel()
            finals.append(self.update_bitcoin_block_task)
        assert self.update_hathor_block_task is not None
        self.update_hathor_block_task.cancel()
        finals.append(self.update_hathor_block_task)
        try:
            await asyncio.gather(*finals)
        except asyncio.CancelledError:
            pass
        except Exception:
            # XXX: ignore cancelled error, not clear what class it will be, depends on the event loop implementation
            #      it's probably not too important to nail down the exact exception
            self.log.warn('exception stopping Hathor task', exc_info=True)

    async def update_bitcoin_block(self) -> None:
        """ Task that continuously polls block templates from bitcoin.get_block_template
        """
        assert self.bitcoin_rpc is not None
        backoff = 1
        longpoll_id = None
        while True:
            self.log.debug('get Bitcoin block template')
            try:
                data = await self.bitcoin_rpc.get_block_template(longpoll_id=longpoll_id)
            except Exception:
                self.log.exception('failed to get Bitcoin Block Template', exc_info=True)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self.MAX_RECONNECT_BACKOFF)
                continue
            else:
                backoff = 1
                longpoll_id = data.get('longpollid')
                self.last_bitcoin_block_received = time.time()
                data_log = data.copy()
                data_log['len(transactions)'] = len(data_log['transactions'])
                del data_log['transactions']
                self.log.debug('bitcoin.getblocktemplate response', res=data_log)
                self.bitcoin_coord_job = BitcoinCoordJob.from_dict(data)
                self.log.debug('new Bitcoin block template', height=self.bitcoin_coord_job.height)
                await self.update_merged_block()
                if longpoll_id is None:
                    self.log.warn('no longpoll_id received, sleep instead')
                    await asyncio.sleep(self.BITCOIN_UPDATE_INTERVAL)

    def update_bitcoin_submitted(self, height: int) -> None:
        """ Used to remember the last height submitted, for use when discarding late winning shares.
        """
        timestamp = time.time()
        if height > self.last_bitcoin_height_submitted:
            self.last_bitcoin_height_submitted = height
            self.last_bitcoin_timestamp_submitted = timestamp

    def should_skip_bitcoin_submit(self, height: int) -> bool:
        """ Check the last submit timestamp and height to decide if the winning share is too late to be submitted.
        """
        timestamp = time.time()
        if height == self.last_bitcoin_height_submitted:
            # if timestamp too into the future, SKIP
            return timestamp - self.last_bitcoin_timestamp_submitted > self.BITCOIN_MAX_FUTURE_SUBMIT_SECONDS
        # if height less than last submission, SKIP
        return height < self.last_bitcoin_height_submitted

    def update_hathor_submitted(self, height: int) -> None:
        """ Used to remember the last height submitted, for use when discarding late winning shares.
        """
        timestamp = time.time()
        if height > self.last_hathor_height_submitted:
            self.last_hathor_height_submitted = height
            self.last_hathor_timestamp_submitted = timestamp

    def should_skip_hathor_submit(self, height: int) -> bool:
        """ Check the last submit timestamp and height to decide if the winning share is too late to be submitted.
        """
        timestamp = time.time()
        if height == self.last_hathor_height_submitted:
            # if timestamp too into the future, SKIP
            return timestamp - self.last_hathor_timestamp_submitted > self.HATHOR_MAX_FUTURE_SUBMIT_SECONDS
        # if height less than last submission, SKIP
        return height < self.last_hathor_height_submitted

    async def update_hathor_block(self) -> None:
        """ Task that continuously reconnects to the mining WS and waits for fresh block templates to update jobs.
        """
        backoff = 1
        while True:
            self.log.debug('connect to Hathor mining')
            try:
                self.hathor_mining = await self.hathor_client.mining()
                backoff = 1
                await self._update_hathor_block(self.hathor_mining)
            except aiohttp.ClientError:
                self.log.warn('lost connection with Hathor', exc_info=True)
            else:
                self.log.warn('lost connection with Hathor')
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.MAX_RECONNECT_BACKOFF)

    async def _update_hathor_block(self, mining: IMiningChannel) -> None:
        async for block_templates in mining:
            self.log.debug('got Hathor block template')
            # TODO: maybe hang on to all templates
            block_template = block_templates.choose_random_template(self.rng)
            address_str = self.payback_address_hathor
            address = decode_address(address_str) if address_str is not None else None
            block = block_template.generate_mining_block(self.rng, address=address, cls=MergeMinedBlock)
            height = block_template.height
            assert isinstance(block, HathorBlock)
            self.last_hathor_block_received = time.time()
            # self.log.debug('hathor.get_block_template response', block=block, height=height)
            self.hathor_coord_job = HathorCoordJob(block, height)
            self.log.debug('new Hathor block template', height=height, weight=block.weight)
            await self.update_merged_block()

    def is_next_job_clean(self) -> bool:
        """ Used to determine if the current job must be immediatly stopped in favor of the next job.

        In practice this is True when height of either block changes, so miners can know their current job would
        probably be thrown away anyway, so they can halt and start mining the next job.
        """
        assert self.bitcoin_coord_job is not None
        assert self.hathor_coord_job is not None
        if self.merged_job is None or self.merged_job.bitcoin_coord is None or self.merged_job.hathor_coord is None:
            return True
        if self.merged_job.bitcoin_coord.height != self.bitcoin_coord_job.height:
            return True
        if self.merged_job.hathor_coord.block.get_block_parent_hash() != \
           self.hathor_coord_job.block.get_block_parent_hash():
            return True
        return False

    async def update_merged_block(self) -> None:
        """ This should be called after either (Hathor/Bitcoin) block template is updated to downstream the changes.
        """
        from hathor.merged_mining.bitcoin import create_output_script as create_output_script_btc
        if self.bitcoin_coord_job is None or self.hathor_coord_job is None:
            self.log.debug('not ready')
            return
        self.job_count += 1
        if self.job_count == 1:
            self.log.info('ready')
        output_script: Optional[bytes]
        if self.payback_address_bitcoin:
            output_script = create_output_script_btc(decode_address(self.payback_address_bitcoin))
        else:
            output_script = None
        merged_job = MergedJob(
            self.hathor_coord_job,
            self.bitcoin_coord_job,
            output_script,
            self.is_next_job_clean(),
        )
        # validate built job
        block_proposal = merged_job.build_sample_block_proposal()
        merkle_root = build_merkle_root(list(tx.txid for tx in block_proposal.transactions))
        if merkle_root != block_proposal.header.merkle_root:
            self.log.warn('bad merkle root', expected=merkle_root.hex(), got=block_proposal.header.merkle_root.hex())
        if self.bitcoin_rpc is not None:
            error = await self.bitcoin_rpc.verify_block_proposal(block=bytes(block_proposal))
            if error is not None:
                self.log.warn('proposed block is invalid, skipping update', error=error)
                return
        self.next_merged_job = merged_job
        self.update_jobs()
        self.log.debug('merged job updated')

    def status(self) -> dict[Any, Any]:
        """ Build status dict with useful metrics for use in MM Status API.
        """
        miners = [p.status() for p in self.miner_protocols.values()]
        total_hashrate_ths = sum(p.hashrate_ths or 0 for p in self.miner_protocols.values())
        return {
            'miners': miners,
            'total_hashrate_ths': total_hashrate_ths,
            'started_at': self.started_at,
            'uptime': self.uptime,
            'bitcoin_job': self.bitcoin_coord_job.to_dict() if self.bitcoin_coord_job else None,
            'hathor_job': self.hathor_coord_job.to_dict() if self.hathor_coord_job else None,
        }
