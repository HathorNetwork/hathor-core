from abc import ABC, abstractmethod
from hashlib import sha256
from json import JSONDecodeError, dumps as json_dumps, loads as json_loads
from math import log
from multiprocessing import Array, Process, Queue as MQueue, Value  # type: ignore
from os import cpu_count
from string import hexdigits
from time import sleep
from typing import TYPE_CHECKING, Any, ClassVar, Dict, List, NamedTuple, Optional, Set, Union, cast
from uuid import UUID, uuid4

from twisted.internet import reactor, task
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress, IDelayedCall, IReactorCore, IReactorTCP
from twisted.internet.protocol import Factory
from twisted.logger import Logger
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.pubsub import EventArguments, HathorEvents
from hathor.transaction import BaseTransaction, Block, Transaction, sum_weights
from hathor.transaction.exceptions import PowError, ScriptError, TxValidationError
from hathor.wallet.exceptions import InvalidAddress

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401

settings = HathorSettings()


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
    data: Array = Array('B', 2048)
    data_size: Value = Value('I')
    job_id: Array = Array('B', 16)
    nonce_size: Value = Value('I')
    weight: Value = Value('d')

    def update_job(self, params: Dict) -> bool:
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
        :type params: Dict

        :return: True if the update is sucessful
        :rtype: bool
        """
        try:
            data = bytes.fromhex(params['data'])
            data_size = len(data)
            self.data[:data_size] = data
            self.data_size.value = data_size
            self.job_id[:] = bytes.fromhex(params['job_id'])
            self.nonce_size.value = int(params['nonce_size'])
            self.weight.value = float(params['weight'])
        except KeyError:
            return False

        return True


class MinerSubmit(NamedTuple):
    """ Data class used to communicate submit data between mining process and supervisor """
    job_id: str
    nonce: str


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

    log = Logger()

    delimiter = b'\n'

    def lineReceived(self, line: bytes) -> None:
        """Receives a line and parses it, checking if it is a valid JSON-RPC 2.0 message.
        If the message is valid, it calls a request, result or error handler.
        Otherwise it sends an appropriate error message to the sender.

        :param line: Bytes of a serialized JSON RPC request
        :type line: bytes

        """
        try:
            data = json_loads(line)
        except JSONDecodeError:
            return self.send_error(PARSE_ERROR, data={'message': line.decode()})

        msgid = data.get('id')

        if 'method' in data:
            return self.handle_request(data['method'], data.get('params'), msgid)

        if 'result' in data:
            if 'error' in data:
                return self.send_error(INVALID_REQUEST,
                                       msgid,
                                       data='Request cannot have result and error simultaneously.')
            return self.handle_result(data['result'], msgid)

        if 'error' in data:
            return self.handle_error(data['error'], data.get('data'), msgid)

        return self.send_error(
            INVALID_REQUEST, data={
                'message': data,
                'error': 'Could not identify message as request, result or error.'
            })

    @abstractmethod
    def handle_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str]) -> None:
        """ Handles any valid request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

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
    def handle_error(self, error: Dict, data: Any, msgid: Optional[str]) -> None:
        """ Handles any valid error.

        :param error: JSON-RPC 2.0 error message
        :type error: Dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        raise NotImplementedError

    def send_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str] = None) -> None:
        """ Sends a JSON-RPC 2.0 request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        data = {'method': method, 'jsonrpc': '2.0', 'params': params}
        self.log.debug('SENDING REQUEST {method} WITH PARAMS {params}', method=method, params=params)
        if msgid is not None:
            data['id'] = msgid
        self.send_json(data)

    def send_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Sends a JSON-RPC 2.0 result.

        :param params: JSON-RPC 2.0 result
        :type params: Any

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        data = {'jsonrpc': '2.0', 'result': result}
        if msgid is not None:
            data['id'] = msgid
        self.log.debug('SENDING REPONSE WITH DATA {data}', data=data)
        return self.send_json(data)

    def send_error(self, error: Dict, msgid: Optional[str] = None, data: Any = None) -> None:
        """ Sends a JSON-RPC 2.0 error.

        :param error: JSON-RPC 2.0 error message
        :type error: Dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        message = {
            'jsonrpc': '2.0',
            'error': error,
            'data': data,
        }
        if msgid is not None:
            message['id'] = msgid
        self.log.info('SENDING ERROR {error} WITH  DATA {data}', error=error, data=data)
        self.send_json(message)

        # Lose connection in case of any native JSON RPC error
        if error['code'] <= -32600 and self.transport is not None:
            self.transport.loseConnection()

    def send_json(self, json: Dict) -> None:
        """ Encodes a JSON and send it through the LineReceiver interface.

        :param json: JSON-RPC 2.0 message
        :type json: Dict
        """
        try:
            message = json_dumps(json).encode()
            self.sendLine(message)
        except TypeError:
            self.log.info('ERROR ENCODING JSON: {json}', json=json)


class StratumProtocol(JSONRPC):
    """
    Twisted protocol that implements server side of Hathor Stratum.
    """

    JOBS_HISTORY = 100
    AVERAGE_JOB_TIME = 1
    MAXIMUM_JOB_TIME = 3

    address: IAddress
    current_job: Optional[ServerJob]
    jobs: Dict[UUID, ServerJob]
    job_ids: List[UUID]
    factory: 'StratumFactory'
    manager: 'HathorManager'
    miner_id: Optional[UUID]
    miner_address: Optional[bytes]
    estimated_hash_rate: float  # log(H/s)
    completed_jobs: int
    connection_start_time: int
    blocks_found: int

    def __init__(self, factory: 'StratumFactory', manager: 'HathorManager', address: IAddress):
        self.factory = factory
        self.manager = manager
        self.address = address

        self.current_job = None
        self.jobs = {}
        self.miner_id = None
        self.miner_address = None
        self.job_ids = []
        self.mine_txs = settings.STRATUM_MINE_TXS_DEFAULT
        self.estimated_hash_rate = 0.0
        self.completed_jobs = 0
        self.connection_start_time = 0
        self.blocks_found = 0

    def connectionMade(self) -> None:
        self.miner_id = uuid4()
        self.log.info('New miner with ID {} from {}'.format(self.miner_id, self.address))
        self.factory.miner_protocols[self.miner_id] = self
        self.connection_start_time = self.factory.get_current_timestamp()

    def connectionLost(self, reason: Failure = None) -> None:
        self.log.info('Miner with ID {} exited'.format(self.miner_id))
        assert self.miner_id is not None
        self.factory.miner_protocols.pop(self.miner_id)

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str]) -> None:
        """ Handles subscribe and submit requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('RECEIVED REQUEST {method} FROM {msgid} WITH PARAMS {params}', msgid=msgid, method=method,
                       params=params)

        if method in ['mining.subscribe', 'subscribe', 'mining.submit', 'submit']:
            if not self.manager.can_start_mining():
                return self.send_error(NODE_SYNCING, msgid)

        if method in ['mining.subscribe', 'subscribe']:
            params = cast(Dict, params)
            return self.handle_subscribe(params, msgid)
        if method in ['mining.submit', 'submit']:
            params = cast(Dict, params)
            return self.handle_submit(params, msgid)

        self.send_error(METHOD_NOT_FOUND, msgid, data={'method': method, 'supported_methods': ['submit', 'subscribe']})

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug('RECEIVED RESULT MESSAGE WITH ID={msgid} RESULT={result}', msgid=msgid, result=result)

    def handle_error(self, error: Dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any errors since there are not supposed to be any """
        self.log.info('RECEIVED ERROR MESSAGE WITH ID={msgid} ERROR={error}', msgid=msgid, error=error)

    def handle_subscribe(self, params: Dict, msgid: Optional[str]) -> None:
        """ Handles subscribe request by answering it and triggering a job request.

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
        assert self.miner_id is not None
        if params and 'address' in params and params['address'] is not None:
            try:
                self.miner_address = decode_address(params['address'])
                self.log.info('Miner with ID {} using address {}'.format(self.miner_id, self.miner_address))
            except InvalidAddress:
                self.send_error(INVALID_ADDRESS, msgid)
                self.transport.loseConnection()
                return
        if params and 'mine_txs' in params:
            self.mine_txs = params['mine_txs']

        self.send_result('ok', msgid)
        self.job_request()

    def handle_submit(self, params: Dict, msgid: Optional[str]) -> None:
        """ Handles submit request by validating and propagating the result

        :param params: a dict containing a valid uui4 hex as `job_id` and a valid transaction nonce as `nonce`
        :type params: Dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[UUID]
        """
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
        # Stratum sends the nonce as a big-endian hexadecimal string.
        tx.nonce = int(params['nonce'], 16)
        tx.update_hash()
        assert tx.hash is not None

        try:
            tx.verify_pow(job.weight)
        except PowError:
            return self.send_error(INVALID_SOLUTION, msgid, {
                'hash': tx.hash.hex(),
                'target': int(tx.get_target()).to_bytes(32, 'big').hex()
            })

        job.submitted = self.factory.get_current_timestamp()
        self.completed_jobs += 1

        try:
            tx.verify_pow()
            if isinstance(tx, Block):
                # We only propagate blocks here in stratum
                # For tx we need to propagate in the resource,
                # so we can get the possible errors
                self.manager.propagate_tx(tx, fails_silently=False)
                self.blocks_found += 1
                return self.send_result('block_found', msgid)
        except (InvalidNewTransaction, TxValidationError, PowError) as e:
            # Transaction propagation failed, but the share was succesfully submited
            self.log.debug('TX VERIFICATION/PROPAGATION FAILED WITH ERROR: {error}', error=e)
            self.send_result('ok', msgid)

            # If we can't propagate the transaction then we should put it in tx queue again
            if isinstance(tx, Transaction):
                funds_hash = tx.get_funds_hash()
                if funds_hash in self.factory.mining_tx_pool and funds_hash not in self.factory.tx_queue:
                    self.factory.tx_queue.append(funds_hash)

            return self.job_request()
        else:
            self.log.info('Stratum new tx/block found: {tx.hash_hex}', tx=tx)

        assert isinstance(tx, Transaction)
        funds_hash = tx.get_funds_hash()

        if funds_hash in self.factory.mining_tx_pool:
            self.factory.mined_txs[funds_hash] = tx
            del self.factory.mining_tx_pool[funds_hash]
            if funds_hash in self.factory.deferreds_tx:
                # Return to resolve the resource to send back the response
                d = self.factory.deferreds_tx.pop(funds_hash)
                d.callback(tx)

        self.send_result('ok', msgid)
        return self.job_request()

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
            self.send_error(INVALID_PARAMS, data={
                'message': str(e)
            })
        else:
            self.send_request('job', {
                'data': job.tx.get_header_without_nonce().hex(),
                'job_id': job.id.hex,
                'nonce_size': job.tx.SERIALIZATION_NONCE_SIZE,
                'weight': float(job.weight),
            })

    def create_job(self) -> ServerJob:
        """
        Creates a job for the designated miner.

        :return: created job
        :rtype: ServerJob
        """
        assert self.miner_id is not None

        jobid = uuid4()

        tx = self.create_job_tx(jobid)
        job = ServerJob(jobid, self.factory.get_current_timestamp(), self.miner_id, tx, 0.0)

        self.current_job = job
        self.jobs[job.id] = job
        self.job_ids.append(job.id)

        share_weight = self.calculate_share_weight()
        job.weight = min(share_weight, tx.weight)

        def jobTimeout(job: ServerJob, protocol: StratumProtocol) -> None:
            if job is protocol.current_job and job.submitted is None:
                # If tx job times out, put tx back in queue
                if isinstance(tx, Transaction):
                    funds_hash = tx.get_funds_hash()
                    if funds_hash in self.factory.mining_tx_pool and funds_hash not in self.factory.tx_queue:
                        self.factory.tx_queue.append(funds_hash)

                # Only send new jobs if miner is still connected
                if self.miner_id in self.factory.miner_protocols:
                    protocol.job_request()

        job.timeoutTask = self.manager.reactor.callLater(self.MAXIMUM_JOB_TIME, jobTimeout, job, self)

        if len(self.job_ids) > self.JOBS_HISTORY:
            del self.jobs[self.job_ids.pop(0)]

        return job

    def create_job_tx(self, jobid: UUID) -> BaseTransaction:
        """
        Creates a BaseTransaction for the designated miner job.

        :return: created BaseTransaction
        :rtype: BaseTransaction
        """
        tx = None
        while not self.should_mine_block() and tx is None:
            funds_hash = self.factory.tx_queue.pop(0)
            tx = self.factory.mining_tx_pool[funds_hash]

        if tx is not None:
            tx.timestamp = self.factory.get_current_timestamp()
            tx.parents = self.manager.get_new_tx_parents(tx.timestamp)
            return tx

        peer_id = self.manager.my_peer.id
        assert peer_id is not None
        assert self.miner_id is not None

        # Only get first 32 bytes of peer_id because block data is limited to 100 bytes
        data = '{}-{}-{}'.format(peer_id[:32], self.miner_id.hex, jobid.hex).encode()[:settings.BLOCK_DATA_MAX_SIZE]
        block = self.manager.generate_mining_block(data=data, address=self.miner_address)
        return block

    def should_mine_block(self) -> bool:
        """
        Calculates whether the next mining job should be an block or not,
        based on the recent history of mined jobs.

        :return: whether the next mining job should be an block or not.
        :rtype: bool
        """
        if len(self.factory.tx_queue) == 0:
            return True

        if not self.mine_txs:
            return True

        # Asure miners won't spend more time on tx jobs than on block jobs
        # Prevents against DoS from tx with huge weight
        tx_acc_weight = 0.0
        block_acc_weight = 0.0

        # Asure miners won't mine more tx jobs than block jobs
        # Prevents against DoS from lots of tx with small weight
        tx_count = 0
        block_count = 0

        for job in self.jobs.values():
            if job.submitted is None:
                continue

            if isinstance(job.tx, Block):
                tx_count += 1
                block_acc_weight = sum_weights(block_acc_weight, job.weight)
            else:
                block_count += 1
                tx_acc_weight = sum_weights(tx_acc_weight, job.weight)

        return block_acc_weight <= tx_acc_weight and tx_count <= block_count

    def calculate_share_weight(self) -> float:
        """
        Calculate the target share weight for the current miner.
        Uses last jobs statistics to aim for an share time equals
        `StratumProtocol.AVERAGE_JOB_TIME`

        :return: job weight for miner to take AVERAGE_JOB_TIME to solve it.
        :rtype: float
        """
        if len(self.job_ids) <= 1:
            return settings.MIN_BLOCK_WEIGHT

        mn = self.jobs[self.job_ids[0]].tx.timestamp
        mx = self.jobs[self.job_ids[-1]].tx.timestamp
        dt = max(mx - mn, 1)

        acc_weight = 0.0
        for job in self.jobs.values():
            if job.submitted is not None:
                acc_weight = sum_weights(acc_weight, job.weight)

        hash_rate = acc_weight - log(dt, 2)
        self.estimated_hash_rate = hash_rate
        return hash_rate + log(self.AVERAGE_JOB_TIME, 2)

    def get_stats(self) -> MinerStatistics:
        assert self.miner_id is not None

        return MinerStatistics(
            address='{}:{}'.format(self.address.host, self.address.port),
            blocks_found=self.blocks_found,
            completed_jobs=self.completed_jobs,
            connection_start_time=self.connection_start_time,
            estimated_hash_rate=self.estimated_hash_rate,
            miner_id=self.miner_id.hex,
        )


class StratumFactory(Factory):
    """
    Twisted factory of server Hathor Stratum protocols.
    Interfaces with nodes to keep mining jobs up to date and to submit successful ones.
    """
    reactor: IReactorTCP
    jobs: Set[UUID]
    manager: 'HathorManager'
    miner_protocols: Dict[UUID, StratumProtocol]
    port: int
    tx_queue: List[bytes]
    mining_tx_pool: Dict[bytes, BaseTransaction]
    mined_txs: Dict[bytes, Transaction]
    deferreds_tx: Dict[bytes, Deferred]

    log: ClassVar[Logger] = Logger()

    def __init__(self, manager: 'HathorManager', port: int, reactor: IReactorTCP = reactor):
        self.manager = manager
        self.port = port
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
        self._listen = self.reactor.listenTCP(self.port, self)

    def stop(self) -> Optional[Deferred]:
        return self._listen.stopListening()

    def mine_transaction(self, tx: Transaction, deferred: Deferred) -> None:
        """
        Puts the transaction in a queue of transactions to be mined via Stratum protocol.
        """
        tx_hash = tx.get_funds_hash()
        if tx_hash in self.mininig_tx_pool:
            self.log.warn('Tried to mine a transaction twice or a twin.')
            return
        self.mining_tx_pool[tx_hash] = tx
        self.tx_queue.append(tx_hash)
        self.deferreds_tx[tx_hash] = deferred

    def get_current_timestamp(self) -> int:
        """
        Gets the current time in seconds
        """
        return int(self.reactor.seconds())

    def get_stats(self) -> List[MinerStatistics]:
        return [protocol.get_stats() for protocol in self.miner_protocols.values()]

    def get_stats_resource(self) -> List[Dict]:
        return [stat._asdict() for stat in self.get_stats()]


class StratumClient(JSONRPC):
    """
    Twisted protocol that implements client side of Hathor Stratum.
    """

    log = Logger()

    # Flags used to send signals to the miner process
    WORK = 0
    SLEEP = 1
    STOP = 2

    SUPERVISOR_LOOP_INTERVAL = 0.3
    NAP_DURATION = 0.1

    queue: MQueue
    proc_count: Optional[int]
    job: Dict
    miners: List[Process]
    loop: Optional[task.LoopingCall]
    signal: Value
    job_data: MinerJob

    address: Optional[bytes]

    def __init__(self, proc_count: Optional[int] = None, address: Optional[bytes] = None):
        self.job_data = MinerJob()
        self.signal = Value('B')
        self.queue = MQueue()
        self.proc_count = proc_count
        self.job = {}
        self.miners = []
        self.loop = None
        self.address = address

    def start(self, clock: IReactorCore = reactor) -> None:
        """
        Starts the client, instantiating mining processes and scheduling miner supervisor calls.
        """
        args = (self.job_data, self.signal, self.queue)
        proc_count = self.proc_count or cast(int, cpu_count())
        self.signal.value = self.SLEEP
        self.miners = [Process(target=miner_job, args=(i, proc_count, *args)) for i in range(proc_count)]

        self.loop = task.LoopingCall(supervisor_job, self)
        self.loop.clock = clock
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
        self.send_request('subscribe', {'address': self.address}, uuid4().hex)

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str]) -> None:
        """ Handles job requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: Hathor Stratum job request params
        :type params: Dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('REQUEST {method} WITH PARAMS {params}', method=method, params=params)

        if method == 'job' and isinstance(params, dict):
            self.job = params
            self.signal.value = self.SLEEP
            self.job_data.update_job(params)
            self.signal.value = self.WORK

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug('RESULT {}'.format(result))

    def handle_error(self, error: Dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any error since there are not supposed to be any """
        self.log.info('ERROR {} DATA {}'.format(error, data))


def miner_job(index: int, process_num: int, job_data: MinerJob, signal: Value, queue: MQueue):
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
    def update_job():
        while signal.value == StratumClient.SLEEP:
            sleep(StratumClient.NAP_DURATION)
        return [
            job_data.job_id[:],  # current_job
            2**(256 - job_data.weight.value) - 1,  # target
            sha256(bytes(job_data.data[:job_data.data_size.value])),  # midstate
            int(index * (1 << (8 * job_data.nonce_size.value)) / process_num),  # start_nonce
            job_data.nonce_size.value  # nonce_size
        ]

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
            client.log.info('Submiting job: {}'.format(data))
            client.send_request('submit', data._asdict(), uuid4().hex)
