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

from abc import ABC, abstractmethod
from hashlib import sha256
from itertools import count
from json import JSONDecodeError
from math import log
from multiprocessing import Process, Queue as MQueue
from multiprocessing.sharedctypes import Array, Value
from os import cpu_count
from string import hexdigits
from time import sleep
from typing import TYPE_CHECKING, Any, Callable, Iterator, NamedTuple, Optional, Union, cast
from uuid import UUID, uuid4

from structlog import get_logger
from twisted.internet import task
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress, IDelayedCall
from twisted.internet.protocol import ServerFactory, connectionDone
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature_service import FeatureService
from hathor.p2p.utils import format_address
from hathor.pubsub import EventArguments, HathorEvents
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction, BitcoinAuxPow, Block, MergeMinedBlock, Transaction, sum_weights
from hathor.transaction.exceptions import PowError, ScriptError, TxValidationError
from hathor.util import json_dumpb, json_loadb
from hathor.verification.vertex_verifier import VertexVerifier
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    import ctypes

    from hathor.manager import HathorManager  # noqa: F401

logger = get_logger()


def valid_uuid(uuid: Any) -> bool:
    """
    Checks if uuid is valid. In other words, checks if it is a string of 32 hex characters.

    :param uuid: object that is checked
    :type uuid: Any

    :return: True if the uuid is valid
    :rtype: bool
    """
    return isinstance(uuid, str) and len(uuid) == 32 and all(c in hexdigits for c in uuid)


def valid_uuid_or_none(uuid: Any) -> bool:
    """
    Checks if uuid is valid or None.
    A valid uuid is a string of 32 hex characters.

    :param uuid: object that is checked
    :type uuid: Any

    :return: True if the uuid is valid
    :rtype: bool
    """
    return uuid is None or valid_uuid(uuid)


UNRECOVERABLE_ERROR_CODE_MAX = -32600

PARSE_ERROR = {'code': -32700, 'message': 'Parse error'}
INTERNAL_ERROR = {'code': -32603, 'message': 'Internal error'}
INVALID_PARAMS = {'code': -32602, 'message': 'Invalid params'}
METHOD_NOT_FOUND = {'code': -32601, 'message': 'Method not found'}
INVALID_REQUEST = {'code': -32600, 'message': 'Invalid Request'}

NODE_SYNCING = {'code': 10, 'message': 'Node syncing'}
INVALID_ADDRESS = {'code': 22, 'message': 'Address to send mined funds is invalid'}
INVALID_SOLUTION = {'code': 30, 'message': 'Invalid solution'}
STALE_JOB = {'code': 31, 'message': 'Stale job submitted'}
JOB_NOT_FOUND = {'code': 32, 'message': 'Job not found'}
PROPAGATION_FAILED = {'code': 33, 'message': 'Solution propagation failed'}
DUPLICATE_SOLUTION = {'code': 34, 'message': 'Solution already submitted'}


class ServerJob:
    """ Data class used to store job info on Stratum servers """
    id: UUID
    created: int
    submitted: Optional[int]
    miner: UUID
    tx: BaseTransaction
    weight: float
    timeoutTask: IDelayedCall

    def __init__(self, jobid: UUID, created: int, miner: UUID, tx: BaseTransaction, weight: float):
        self.id = jobid
        self.created = created
        self.miner = miner
        self.tx = tx
        self.submitted = None
        self.weight = weight


class MinerJob(NamedTuple):
    """ Data class used to share job data between mining processes """
    # XXX: these typings are causing too much trouble, since this module hasn't been touched for a while and won't be
    #      touched for the foreseeable future (and will possibly even removed before any changes) it seems fine to just
    #      use Any so there aren't any mypy complaints anymore
    data: Any = Array('B', 2048)
    data_size: Any = Value('I')
    job_id: Any = Array('B', 16)
    nonce_size: Any = Value('I')
    weight: Any = Value('d')

    def update_job(self, params: dict[str, Any]) -> bool:
        """
        Updates job variables shared between processes.
        Should contain the following params:
        {
            data: str,
            job_id: str,
            nonce_size: int,
            weigth: float
        }

        :param params: Hathor Stratum job method request params
        :type params: dict

        :return: True if the update is sucessful
        :rtype: bool
        """
        try:
            data = bytes.fromhex(params['data'])
            data_size: int = len(data)
            self.data[:data_size] = list(data)
            self.data_size.value = data_size
            self.job_id[:] = list(bytes.fromhex(params['job_id']))
            self.nonce_size.value = int(params['nonce_size'])
            self.weight.value = float(params['weight'])
        except KeyError:
            return False

        return True


class MinerSubmit(NamedTuple):
    """ Data class used to communicate submit data between mining process and supervisor """
    job_id: str
    # either nonce or aux_proof must be given
    nonce: str = ''
    aux_pow: str = ''


class MinerStatistics(NamedTuple):
    """ Data class used to store data about a miner """
    address: str
    blocks_found: int
    completed_jobs: int
    connection_start_time: int
    # Not acutally H/2, but really log_2(H/s)
    estimated_hash_rate: float
    miner_id: str


class JSONRPC(LineReceiver, ABC):
    """
    JSONRPC implements basic functionality of JSON-RPC 2.0 Specification based on Twisted's LineReceiver.
    """

    delimiter = b'\n'
    use_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log = logger.new()

    def lineReceived(self, line: bytes) -> None:
        """Receives a line and parses it, checking if it is a valid JSON-RPC 2.0 message.
        If the message is valid, it calls a request, result or error handler.
        Otherwise it sends an appropriate error message to the sender.

        :param line: Bytes of a serialized JSON RPC request
        :type line: bytes

        """
        self.log.debug('line received', line=line)
        try:
            data = json_loadb(line)
        except JSONDecodeError:
            return self.send_error(PARSE_ERROR, data={'message': repr(line)})
        assert isinstance(data, dict)

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

    @abstractmethod
    def handle_request(self, method: str, params: Optional[Union[list, dict]], msgid: Optional[str]) -> None:
        """ Handles any valid request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[list, dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        raise NotImplementedError

    @abstractmethod
    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Handles any valid result.

        :param params: JSON-RPC 2.0 result
        :type params: Any

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        raise NotImplementedError

    @abstractmethod
    def handle_error(self, error: dict, data: Any, msgid: Optional[str]) -> None:
        """ Handles any valid error.

        :param error: JSON-RPC 2.0 error message
        :type error: dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        raise NotImplementedError

    def send_request(self, method: str, params: Optional[Union[list, dict]], msgid: Union[str, int, None] = None,
                     ok: Optional[bool] = None) -> None:
        """ Sends a JSON-RPC 2.0 request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[list, dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        data: dict[str, Any] = {'method': method, 'params': params}
        self.log.debug('send request', method=method, params=params)
        # XXX: keeping the same msgid type the client sent
        data['id'] = msgid
        if ok is True:
            data['result'] = 'ok' if self.use_ok else True
        self.send_json(data)

    def send_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Sends a JSON-RPC 2.0 result.

        :param params: JSON-RPC 2.0 result
        :type params: Any

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        data = {'result': result, 'error': None}
        if msgid is not None:
            data['id'] = msgid
        self.log.debug('send result', data=data)
        return self.send_json(data)

    def send_error(self, error: dict, msgid: Optional[str] = None, data: Any = None) -> None:
        """ Sends a JSON-RPC 2.0 error.

        :param error: JSON-RPC 2.0 error message
        :type error: dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        message = {'error': error, 'data': data}
        if msgid is not None:
            message['id'] = msgid
        self.log.info('send_error', error=error, data=data)
        self.send_json(message)

        # Lose connection in case of any native JSON RPC error
        if error['code'] <= UNRECOVERABLE_ERROR_CODE_MAX and self.transport is not None:
            self.transport.loseConnection()

    def send_json(self, json: dict) -> None:
        """ Encodes a JSON and send it through the LineReceiver interface.

        :param json: JSON-RPC 2.0 message
        :type json: dict
        """
        try:
            message = json_dumpb(json)
            self.log.debug('send line', line=message)
            self.sendLine(message)
        except TypeError:
            self.log.error('failed to encode', json=json)


class StratumProtocol(JSONRPC):
    """
    Twisted protocol that implements server side of Hathor Stratum.

    References:
    - https://en.bitcoinwiki.org/wiki/Stratum_mining_protocol
    - https://en.bitcoin.it/wiki/Stratum_mining_protocol
    - https://slushpool.com/help/stratum-protocol/
    """

    JOBS_HISTORY = 100
    AVERAGE_JOB_TIME = 5
    BLOCK_MAXIMUM_JOB_TIME = 15
    # we use a short timeout period when mining txs because the nonce is only 4 bytes
    TX_MAXIMUM_JOB_TIME = 1

    address: IAddress
    current_job: Optional[ServerJob]
    jobs: dict[UUID, ServerJob]
    job_ids: list[UUID]
    factory: 'StratumFactory'
    manager: 'HathorManager'
    miner_id: Optional[UUID]
    miner_address: Optional[bytes]
    estimated_hash_rate: float  # log(H/s)
    completed_jobs: int
    connection_start_time: int
    blocks_found: int
    merged_mining: bool

    def __init__(self, factory: 'StratumFactory', manager: 'HathorManager', address: IAddress,
                 id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count()):
        self._settings = get_global_settings()
        self.log = logger.new(address=address)
        self.factory = factory
        self.manager = manager
        self.address = address

        self.current_job = None
        self.jobs = {}
        self.miner_id = None
        self.miner_address = None
        self.job_ids = []
        self.mine_txs = self._settings.STRATUM_MINE_TXS_DEFAULT
        self.estimated_hash_rate = 0.0
        self.completed_jobs = 0
        self.connection_start_time = 0
        self.blocks_found = 0
        self._iter_id = id_generator and id_generator() or None
        self.subscribed = False

    def _next_id(self):
        if self._iter_id:
            return str(next(self._iter_id))

    def connectionMade(self) -> None:
        self.miner_id = uuid4()
        self.connection_start_time = self.factory.get_current_timestamp()
        self.log = self.log.bind(miner_id=self.miner_id, conn_at=self.connection_start_time, address=self.address)
        self.log.debug('new connection')

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        if self.subscribed:
            self.log.info('miner disconnected')
        assert self.miner_id is not None
        self.factory.miner_protocols.pop(self.miner_id, None)

    def handle_request(self, method: str, params: Optional[Union[list, dict]], msgid: Optional[str]) -> None:
        """ Handles subscribe and submit requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[list, dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('handle request', msgid=msgid, method=method, params=params)

        if method in ['mining.subscribe', 'subscribe', 'mining.submit', 'submit']:
            if not self.manager.can_start_mining():
                return self.send_error(NODE_SYNCING, msgid)

        if not isinstance(params, dict):
            self.log.error(f'expected dict params, received: {params}')
            params = cast(dict, params)

        if method in ['mining.subscribe', 'subscribe']:
            return self.handle_subscribe(params, msgid)
        if method in ['mining.submit', 'submit']:
            return self.handle_submit(params, msgid)

        self.send_error(METHOD_NOT_FOUND, msgid, data={'method': method, 'supported_methods': ['submit', 'subscribe']})

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug('handle result', msgid=msgid, result=result)

    def handle_error(self, error: dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any errors since there are not supposed to be any """
        self.log.error('handle error', msgid=msgid, error=error)

    def handle_subscribe(self, params: dict, msgid: Optional[str]) -> None:
        """ Handles subscribe request by answering it and triggering a job request.

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        assert self.miner_id is not None
        self.log.debug('handle subscribe', msgid=msgid, params=params)
        if params and 'address' in params and params['address'] is not None:
            try:
                address = params['address']
                self.miner_address = decode_address(address)
                self.log.debug('miner with address', id=self.miner_id, address=address)
            except InvalidAddress:
                self.send_error(INVALID_ADDRESS, msgid)
                assert self.transport is not None
                self.transport.loseConnection()
                return
        if params and 'mine_txs' in params:
            self.mine_txs = params['mine_txs']
        if params and 'merged_mining' in params:
            self.merged_mining = params['merged_mining']
        else:
            self.merged_mining = False
        if params and params.get('mine_txs') and params.get('merged_mining'):
            err = INVALID_PARAMS.copy()
            err['message'] = 'Cannot set both merged_mining=True and mine_txs=True'
            return self.send_error(err, msgid)
        if self.merged_mining:
            self.log.debug('merged_mining=True implies mine_txs=False')
            self.mine_txs = False
        self.factory.miner_protocols[self.miner_id] = self
        self.log.info('miner subscribed', address=self.miner_address, mine_txs=self.mine_txs,
                      merged_mining=self.merged_mining)
        self.send_result('ok', msgid)
        self.subscribed = True
        self.job_request()

    def handle_submit(self, params: dict, msgid: Optional[str]) -> None:
        """ Handles submit request by validating and propagating the result

        :param params: a dict containing a valid uui4 hex as `job_id` and a valid transaction nonce as `nonce`
        :type params: dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        from hathor.merged_mining.bitcoin import sha256d_hash

        self.log.debug('handle submit', msgid=msgid, params=params)

        if 'job_id' not in params or 'nonce' not in params:
            return self.send_error(INVALID_PARAMS, msgid, {'params': params, 'required': ['job_id', 'nonce']})

        if not valid_uuid(params['job_id']):
            return self.send_error(INVALID_PARAMS, msgid, {
                'job_id': params['job_id'],
                'message': 'job_id is invalid uuid4'
            })

        job_id = UUID(params['job_id'])
        job = self.jobs.get(job_id)

        if job is None:
            return self.send_error(JOB_NOT_FOUND, msgid, {
                'current_job': self.current_job and self.current_job.id.hex,
                'job_id': job_id.hex
            })

        # It may take a while for pubsub to get a new job.
        # To avoid propagating the same tx multiple times, we check if it has already been submitted.
        if job is not self.current_job or job.submitted is not None:
            return self.send_error(STALE_JOB, msgid, {
                'current_job': self.current_job and self.current_job.id.hex,
                'job_id': job_id.hex
            })

        tx = job.tx.clone()
        block_base = tx.get_mining_header_without_nonce()
        block_base_hash = sha256d_hash(block_base)
        # Stratum sends the nonce as a big-endian hexadecimal string.
        if params.get('aux_pow'):
            assert isinstance(tx, MergeMinedBlock), 'expected MergeMinedBlock got ' + type(tx).__name__
            tx.aux_pow = BitcoinAuxPow.from_bytes(bytes.fromhex(params['aux_pow']))
            tx.nonce = 0
        else:
            tx.nonce = int(params['nonce'], 16)
        tx.update_hash()

        self.log.debug('share received', block=tx, block_base=block_base.hex(), block_base_hash=block_base_hash.hex())

        feature_service = FeatureService(settings=self._settings, tx_storage=self.manager.tx_storage)
        verifier = VertexVerifier(
            reactor=self.manager.reactor,
            settings=self._settings,
            feature_service=feature_service
        )

        try:
            verifier.verify_pow(tx, override_weight=job.weight)
        except PowError:
            self.log.error('bad share, discard', job_weight=job.weight, tx=tx)
            return self.send_error(INVALID_SOLUTION, msgid, {
                'hash': tx.hash.hex(),
                'target': int(tx.get_target()).to_bytes(32, 'big').hex()
            })

        job.submitted = self.factory.get_current_timestamp()
        self.completed_jobs += 1

        # answer the miner soon, so it can start a new job
        self.send_result('ok', msgid)
        self.manager.reactor.callLater(0, self.job_request)

        try:
            verifier.verify_pow(tx)
        except PowError:
            # Transaction pow was not enough, but the share was successfully submitted
            self.log.info('high hash, keep mining', tx=tx)
            return
        else:
            self.log.info('low hash, new block candidate', tx=tx)

        if isinstance(tx, Block):
            try:
                # We only propagate blocks here in stratum
                # For tx we need to propagate in the resource,
                # so we can get the possible errors
                self.manager.submit_block(tx)
                self.blocks_found += 1
            except (InvalidNewTransaction, TxValidationError) as e:
                # Block propagation failed, but the share was successfully submitted
                self.log.warn('block propagation failed', block=tx, error=e)
            else:
                self.log.info('new block found', block=tx)
        elif isinstance(tx, Transaction):
            self.log.info('transaction mined', tx=tx)
            funds_hash = tx.get_funds_hash()
            if funds_hash in self.factory.mining_tx_pool:
                self.factory.mined_txs[funds_hash] = tx
                del self.factory.mining_tx_pool[funds_hash]
                if funds_hash in self.factory.tx_queue:
                    self.factory.tx_queue.remove(funds_hash)
                if funds_hash in self.factory.deferreds_tx:
                    # Return to resolve the resource to send back the response
                    d = self.factory.deferreds_tx.pop(funds_hash)
                    d.callback(tx)
        else:
            assert False, 'tx should either be a Block or Transaction'

    def job_request(self) -> None:
        """ Sends a job request to the connected client

        :param job: data representing the mining job
        :type job: ServerJob
        """
        try:
            job = self.create_job()
        except (ValueError, ScriptError) as e:
            # ScriptError might happen if try to use a mainnet address in the testnet or vice versa
            # ValueError happens if address is not a valid base58 address
            # FIXME: I don't think the stratum server should send an unprompted error to the client
            self.send_error(INVALID_PARAMS, data={
                'message': str(e)
            })
        else:
            if job:
                job_data = {
                    'data': job.tx.get_mining_header_without_nonce().hex(),
                    'job_id': job.id.hex,
                    'nonce_size': job.tx.SERIALIZATION_NONCE_SIZE,
                    'weight': float(job.weight),
                }
                if job.tx.is_block:
                    assert isinstance(job.tx, Block)
                    job_data['parent_hash'] = job.tx.get_block_parent_hash().hex()
                self.send_request('job', job_data, self._next_id())

    def create_job(self) -> ServerJob:
        """
        Creates a job for the designated miner.

        :return: created job
        :rtype: ServerJob
        """
        assert self.miner_id is not None

        # before creating the job, make sure we cancel any outstanding timeout
        self.cancel_current_job_timeout()

        jobid = uuid4()
        tx = self.create_job_tx(jobid)
        job = ServerJob(jobid, self.factory.get_current_timestamp(), self.miner_id, tx, 0.0)

        self.current_job = job
        self.jobs[job.id] = job
        self.job_ids.append(job.id)

        share_weight = self.calculate_share_weight()
        job.weight = min(share_weight, tx.weight)

        def jobTimeout(job: ServerJob, protocol: StratumProtocol) -> None:
            if job is protocol.current_job and job.submitted is None:  # allow-is
                # Only send new jobs if miner is still connected
                if self.miner_id in self.factory.miner_protocols:
                    protocol.job_request()

        timeout = self.BLOCK_MAXIMUM_JOB_TIME if tx.is_block else self.TX_MAXIMUM_JOB_TIME
        job.timeoutTask = self.manager.reactor.callLater(timeout, jobTimeout, job, self)

        if len(self.job_ids) > self.JOBS_HISTORY:
            del self.jobs[self.job_ids.pop(0)]

        return job

    def create_job_tx(self, jobid: UUID) -> BaseTransaction:
        """
        Creates a BaseTransaction for the designated miner job.

        :return: created BaseTransaction
        :rtype: BaseTransaction
        """
        # if there's a tx, always mine it. Blocks are not priority
        if self.mine_txs and self.factory.tx_queue:
            # we're always returning the first tx on the queue and we don't remove it. It will only be removed
            # when the job is done or times out. This means that 2 different miners will work on the same tx.
            funds_hash = self.factory.tx_queue[0]
            tx = self.factory.mining_tx_pool[funds_hash]
            tx.timestamp = self.factory.get_current_timestamp()
            tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
            self.log.debug('prepared tx for mining', tx=tx)
            return tx

        peer_id = self.manager.my_peer.id
        assert peer_id is not None
        assert self.miner_id is not None

        # Only get first 32 bytes of peer_id because block data is limited to 100 bytes
        data = '{}-{}-{}'.format(str(peer_id)[:32], self.miner_id.hex, jobid.hex).encode()
        data = data[:self._settings.BLOCK_DATA_MAX_SIZE]
        block = self.manager.generate_mining_block(data=data, address=self.miner_address,
                                                   merge_mined=self.merged_mining)
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        self.log.debug('prepared block for mining', block=block)
        return block

    def cancel_current_job_timeout(self) -> None:
        """ Cancel current's job timeout, if it exists
        """
        if self.current_job and self.current_job.timeoutTask and self.current_job.timeoutTask.active():
            self.current_job.timeoutTask.cancel()

    def calculate_share_weight(self) -> float:
        """
        Calculate the target share weight for the current miner.
        Uses last jobs statistics to aim for an share time equals
        `StratumProtocol.AVERAGE_JOB_TIME`

        :return: job weight for miner to take AVERAGE_JOB_TIME to solve it.
        :rtype: float
        """
        if len(self.job_ids) <= 1:
            return self._settings.MIN_BLOCK_WEIGHT

        mn = self.jobs[self.job_ids[0]].tx.timestamp
        mx = self.jobs[self.job_ids[-1]].tx.timestamp
        dt = max(mx - mn, 1)

        acc_weight = 0.0
        for job in self.jobs.values():
            if job.submitted is not None:
                acc_weight = sum_weights(acc_weight, job.weight)

        hash_rate = acc_weight - log(dt, 2)
        self.estimated_hash_rate = hash_rate
        share_weight = hash_rate + log(self.AVERAGE_JOB_TIME, 2)
        share_weight = max(share_weight, self._settings.MIN_SHARE_WEIGHT)
        return share_weight

    def get_stats(self) -> MinerStatistics:
        assert self.miner_id is not None

        return MinerStatistics(
            address=format_address(self.address),
            blocks_found=self.blocks_found,
            completed_jobs=self.completed_jobs,
            connection_start_time=self.connection_start_time,
            estimated_hash_rate=self.estimated_hash_rate,
            miner_id=self.miner_id.hex,
        )


class StratumFactory(ServerFactory):
    """
    Twisted factory of server Hathor Stratum protocols.
    Interfaces with nodes to keep mining jobs up to date and to submit successful ones.
    """
    reactor: Reactor
    jobs: set[UUID]
    manager: 'HathorManager'
    miner_protocols: dict[UUID, StratumProtocol]
    tx_queue: list[bytes]
    mining_tx_pool: dict[bytes, BaseTransaction]
    mined_txs: dict[bytes, Transaction]
    deferreds_tx: dict[bytes, Deferred]

    def __init__(self, manager: 'HathorManager', reactor: Reactor):
        self.log = logger.new()
        self.manager = manager
        self.reactor = reactor

        self.jobs = set()
        self.miner_protocols = {}
        self.tx_queue = []
        self.mining_tx_pool = {}
        self.mined_txs = {}

        # This dict stores all the deferreds from the resource that must be called after mining a tx
        self.deferreds_tx = {}

    def buildProtocol(self, addr: IAddress) -> StratumProtocol:
        protocol = StratumProtocol(self, self.manager, addr)
        return protocol

    def update_jobs(self) -> None:
        """
        Creates and sends a new job for each subscribed miner.
        """
        for miner, protocol in self.miner_protocols.items():
            if protocol.subscribed:
                protocol.job_request()

    def start(self) -> None:
        """
        Starts the Hathor Stratum server and subscribes for new blocks on the network in order to update miner jobs.
        """
        def on_new_block(event: HathorEvents, args: EventArguments) -> None:
            tx = args.__dict__['tx']
            if isinstance(tx, Block):
                self.update_jobs()

        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, on_new_block)

    def stop(self) -> Optional[Deferred]:
        return None

    def mine_transaction(self, tx: Transaction, deferred: Deferred) -> None:
        """
        Puts the transaction in a queue of transactions to be mined via Stratum protocol.
        """
        self.log.info('mine transaction', tx=tx)
        tx_hash = tx.get_funds_hash()
        if tx_hash in self.mining_tx_pool:
            self.log.warn('tried to mine a transaction twice or a twin')
            return
        self.mining_tx_pool[tx_hash] = tx
        self.tx_queue.append(tx_hash)
        self.deferreds_tx[tx_hash] = deferred

    def get_current_timestamp(self) -> int:
        """
        Gets the current time in seconds
        """
        return int(self.reactor.seconds())

    def get_stats(self) -> list[MinerStatistics]:
        return [protocol.get_stats() for protocol in self.miner_protocols.values()]

    def get_stats_resource(self) -> list[dict]:
        return [stat._asdict() for stat in self.get_stats()]


class StratumClient(JSONRPC):
    """
    Twisted protocol that implements client side of Hathor Stratum.
    """

    # Flags used to send signals to the miner process
    WORK = 0
    SLEEP = 1
    STOP = 2

    SUPERVISOR_LOOP_INTERVAL = 0.3
    NAP_DURATION = 0.1

    queue: MQueue
    proc_count: Optional[int]
    job: dict
    miners: list[Process]
    loop: Optional[task.LoopingCall]
    signal: Any
    job_data: MinerJob

    address: Optional[bytes]

    def __init__(self, reactor: Reactor, proc_count: Optional[int] = None, address: Optional[bytes] = None,
                 id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count()):
        self.log = logger.new()
        self.job_data = MinerJob()
        self.signal = Value('B')
        self.queue = MQueue()
        self.proc_count = proc_count
        self.job = {}
        self.miners = []
        self.loop = None
        self.address = address
        self._iter_id = id_generator and id_generator() or None
        self.reactor = reactor

    def _next_id(self):
        if self._iter_id:
            return str(next(self._iter_id))

    def start(self) -> None:
        """
        Starts the client, instantiating mining processes and scheduling miner supervisor calls.
        """
        args = (self.job_data, self.signal, self.queue)
        proc_count = self.proc_count or cast(int, cpu_count())
        self.signal.value = self.SLEEP
        self.miners = [Process(target=miner_job, args=(i, proc_count, *args)) for i in range(proc_count)]

        self.loop = task.LoopingCall(supervisor_job, self)
        self.loop.clock = self.reactor
        self.loop.start(self.SUPERVISOR_LOOP_INTERVAL)

        for miner in self.miners:
            miner.start()

    def stop(self) -> None:
        """
        Stops the client, interrupting mining processes, stoping supervisor loop , and sending finished jobs
        """
        if self.loop:
            self.loop.stop()

        self.signal.value = self.STOP
        supervisor_job(self)
        for miner in self.miners:
            miner.join()

    def connectionMade(self) -> None:
        self.send_request('subscribe', {'address': self.address}, self._next_id())

    def handle_request(self, method: str, params: Optional[Union[list, dict]], msgid: Optional[str]) -> None:
        """ Handles job requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: Hathor Stratum job request params
        :type params: dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('handle request', method=method, params=params)

        if method == 'job' and isinstance(params, dict):
            self.job = params
            self.signal.value = self.SLEEP
            self.job_data.update_job(params)
            self.signal.value = self.WORK

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug('handle result', result=result)

    def handle_error(self, error: dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any error since there are not supposed to be any """
        self.log.warn('handle_error', error=error, data=data)


def miner_job(index: int, process_num: int, job_data: MinerJob, signal: 'ctypes.c_ubyte', queue: MQueue) -> None:
    """
    Job to be executed by the mining process.

    :param index: index of the mining process
    :type index: int

    :param process_num: total number of mining processes
    :type process_num: int

    :param job_data: data used to execute the mining job
    :type job_data: MinerJob

    :param signal: signal used to coordinate the job.
    One of StratumClient.SLEEP, StratumClient.WORK or StratumClient.STOP.
    :type signal: Value

    :param queue: queue used to submit solutions to supervisor process
    :type queue: MQueue
    """
    def update_job() -> tuple[bytes, int, Any, int, int]:
        while signal.value == StratumClient.SLEEP:
            sleep(StratumClient.NAP_DURATION)
        return (
            bytes(job_data.job_id[:]),  # current_job
            int(2**(256 - job_data.weight.value)) - 1,  # target
            sha256(bytes(job_data.data[:job_data.data_size.value])),  # midstate
            int(index * (1 << (8 * job_data.nonce_size.value)) / process_num),  # start_nonce
            job_data.nonce_size.value  # nonce_size
        )

    while signal.value != StratumClient.STOP:
        current_job, target, base, nonce, nonce_size = update_job()
        while signal.value == StratumClient.WORK and current_job == job_data.job_id[:]:
            hash = base.copy()
            hash.update(nonce.to_bytes(nonce_size, 'big'))
            if int(sha256(hash.digest()).digest()[::-1].hex(), 16) < target:
                queue.put(MinerSubmit(job_id=bytes(current_job).hex(), nonce=hex(nonce)))
            nonce += 1


def supervisor_job(client: StratumClient) -> None:
    """
    Job to be executed periodically to submit complete mining jobs.

    :param client: client that executes the supervisor job.
    :type client: StratumClient
    """
    while not client.queue.empty():
        data = client.queue.get()
        assert isinstance(data, MinerSubmit)
        if data.job_id == client.job['job_id']:
            client.log.info('submit job', job=data)
            client.send_request('submit', data._asdict(), client._next_id())
