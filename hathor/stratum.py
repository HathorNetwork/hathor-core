from abc import ABC, abstractmethod
from hashlib import sha256
from json import JSONDecodeError, dumps as json_dumps, loads as json_loads
from multiprocessing import Array, Process, Queue as MQueue, Value  # type: ignore
from os import cpu_count
from queue import Queue
from string import hexdigits
from time import sleep
from typing import TYPE_CHECKING, Any, ClassVar, Dict, List, NamedTuple, Optional, Set, Union, cast
from uuid import UUID, uuid4

from twisted.internet import reactor, task
from twisted.internet.interfaces import IAddress, IReactorCore, IReactorTCP
from twisted.internet.protocol import Factory
from twisted.logger import Logger
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.pubsub import EventArguments, HathorEvents
from hathor.transaction import Block
from hathor.transaction.exceptions import PowError, TxValidationError
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


PARSE_ERROR = {"code": -32700, "message": "Parse error"}
INTERNAL_ERROR = {"code": -32603, "message": "Internal error"}
INVALID_PARAMS = {"code": -32602, "message": "Invalid params"}
METHOD_NOT_FOUND = {"code": -32601, "message": "Method not found"}
INVALID_REQUEST = {"code": -32600, "message": "Invalid Request"}

INVALID_ADDRESS = {"code": 22, "message": "Address to send mined funds is invalid"}
INVALID_SOLUTION = {"code": 30, "message": "Invalid solution"}
STALE_JOB = {"code": 31, "message": "Stale job submitted"}
JOB_NOT_FOUND = {"code": 32, "message": "Job not found"}
PROPAGATION_FAILED = {"code": 33, "message": "Solution propagation failed"}


class ServerJob:
    """ Data class used to store job info on Stratum servers """
    id: UUID
    submitted: bool
    miner: UUID
    block: Block

    def __init__(self, id: UUID, miner: UUID, block: Block):
        self.id = id
        self.miner = miner
        self.block = block
        self.submitted = False


class MinerJob(NamedTuple):
    """ Data class used to share job data between mining processes """
    data: Array = Array("B", 2048)
    data_size: Value = Value("I")
    job_id: Array = Array("B", 16)
    nonce_size: Value = Value("I")
    weight: Value = Value("d")

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
            data = bytes.fromhex(params["data"])
            data_size = len(data)
            self.data[:data_size] = data
            self.data_size.value = data_size
            self.job_id[:] = bytes.fromhex(params["job_id"])
            self.nonce_size.value = int(params["nonce_size"])
            self.weight.value = float(params["weight"])
        except KeyError:
            return False

        return True


class MinerSubmit(NamedTuple):
    """ Data class used to communicate submit data between mining process and supervisor """
    job_id: str
    nonce: str


class JSONRPC(LineReceiver, ABC):
    """
    JSONRPC implements basic functionality of JSON-RPC 2.0 Specification based on Twisted"s LineReceiver.
    """

    log = Logger()

    delimiter = b'\n'

    def lineReceived(self, line: bytes) -> None:
        """Receives a line and parses it, checking if it is a valid JSON-RPC 2.0 message.
        If the message is valid, it calls a request, result or error handler.
        Otherwise it sends an appropriate error message to the sender.


        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A transaction or a block, depending on the class `cls`

        :raises ValueError: when the sequence of bytes is incorrect
        """
        try:
            data = json_loads(line)
        except JSONDecodeError:
            return self.send_error(PARSE_ERROR, data={"message": line.decode()})

        if "id" in data and not valid_uuid_or_none(data["id"]):
            return self.send_error(INVALID_REQUEST, data["id"], {"id": data["id"], "message": "id is invalid uuid4"})

        id = UUID(data["id"]) if "id" in data else None

        if "jsonrpc" not in data or data["jsonrpc"] != "2.0":
            return self.send_error(INVALID_REQUEST, id, data={"request": data, "required": {"jsonrpc": "2.0"}})

        if "method" in data:
            return self.handle_request(data["method"], data.get("params"), id)

        if "result" in data:
            if "error" in data:
                return self.send_error(INVALID_REQUEST,
                                       id,
                                       data="Request cannot have result and error simultaneously.")
            return self.handle_result(data["result"], id)

        if "error" in data:
            return self.handle_error(data["error"], data.get("data"), id)

        return self.send_error(
            INVALID_REQUEST, data={
                "message": data,
                "error": "Could not identify message as request, result or error."
            })

    @abstractmethod
    def handle_request(self, method: str, params: Optional[Union[List, Dict]], id: Optional[UUID]) -> None:
        """ Handles any valid request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        raise NotImplementedError

    @abstractmethod
    def handle_result(self, result: Any, id: Optional[UUID]) -> None:
        """ Handles any valid result.

        :param params: JSON-RPC 2.0 result
        :type params: Any

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        raise NotImplementedError

    @abstractmethod
    def handle_error(self, error: Dict, data: Any, id: Optional[UUID]) -> None:
        """ Handles any valid error.

        :param error: JSON-RPC 2.0 error message
        :type error: Dict

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        raise NotImplementedError

    def send_request(self, method: str, params: Optional[Union[List, Dict]], id: Optional[UUID] = None) -> None:
        """ Sends a JSON-RPC 2.0 request.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        data = {"method": method, "jsonrpc": "2.0", "params": params}
        self.log.debug("SENDING REQUEST {method} WITH PARAMS {params}", method=method, params=params)
        if id is not None:
            data["id"] = id.hex
        self.send_json(data)

    def send_result(self, result: Any, id: Optional[UUID]) -> None:
        """ Sends a JSON-RPC 2.0 result.

        :param params: JSON-RPC 2.0 result
        :type params: Any

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        data = {"jsonrpc": "2.0", "id": id.hex if isinstance(id, UUID) else id, "result": result}
        self.log.debug("SENDING REPONSE WITH DATA {data}", data=data)
        return self.send_json(data)

    def send_error(self, error: Dict, id: Optional[UUID] = None, data: Any = None) -> None:
        """ Sends a JSON-RPC 2.0 error.

        :param error: JSON-RPC 2.0 error message
        :type error: Dict

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        message = {
            "jsonrpc": "2.0",
            "id": id.hex if isinstance(id, UUID) else id,
            "error": error,
            "data": data,
        }
        # self.log.info("SENDING ERROR {error} WITH  DATA {data}", error=error, data=data)
        self.send_json(message)

        # Lose connection in case of any native JSON RPC error
        if error["code"] <= -32600 and self.transport is not None:
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
            self.log.info("ERROR ENCODING JSON: {json}", json=json)


class StratumProtocol(JSONRPC):
    """
    Twisted protocol that implements server side of Hathor Stratum.
    """

    JOBS_HISTORY = 10

    address: IAddress
    current_job: Optional[ServerJob]
    jobs: Dict[UUID, ServerJob]
    job_queue: Queue
    factory: "StratumFactory"
    manager: "HathorManager"
    miner_id: Optional[UUID]
    miner_address: Optional[bytes]

    def __init__(self, factory: "StratumFactory", manager: "HathorManager", address: IAddress):
        self.factory = factory
        self.manager = manager
        self.address = address

        self.current_job = None
        self.jobs = {}
        self.miner_id = None
        self.miner_address = None
        self.job_queue = Queue()

    def connectionMade(self) -> None:
        self.miner_id = uuid4()
        self.log.info("New miner with ID {} from address {}".format(self.miner_id, self.address))
        self.factory.miner_protocols[self.miner_id] = self

    def connectionLost(self, reason: Failure = None) -> None:
        self.log.info("Miner with ID {} exited".format(self.miner_id))
        assert self.miner_id is not None
        self.factory.miner_protocols.pop(self.miner_id)

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], id: Optional[UUID]) -> None:
        """ Handles subscribe and submit requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        self.log.debug("RECEIVED REQUEST {method} WITH PARAMS {params}", method=method, params=params)

        if method == "subscribe":
            params = cast(Dict, params)
            return self.handle_subscribe(params, id)
        if method == "submit":
            params = cast(Dict, params)
            return self.handle_submit(params, id)

        self.send_error(METHOD_NOT_FOUND, id, data={"method": method, "supported_methods": ["submit", "subscribe"]})

    def handle_result(self, result: Any, id: Optional[UUID]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug("RECEIVED RESULT MESSAGE WITH ID={id} RESULT={result}", id=result, result=result)

    def handle_error(self, error: Dict, data: Any, id: Optional[UUID]) -> None:
        """ Logs any errors since there are not supposed to be any """
        self.log.info("RECEIVED ERROR MESSAGE WITH ID={id} ERROR={error}", id=id, error=error)

    def handle_subscribe(self, params: Dict, id: Optional[UUID]) -> None:
        """ Handles subscribe request by answering it and triggering a job request.

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        assert self.miner_id is not None
        if params and "address" in params and params["address"] is not None:
            try:
                self.miner_address = decode_address(params["address"])
            except InvalidAddress:
                self.send_error(INVALID_ADDRESS, id)
                self.transport.loseConnection()
                return

        job = self.factory.create_job(self.miner_id, self.miner_address)
        self.send_result("ok", id)
        self.job_request(job)

    def handle_submit(self, params: Dict, id: Optional[UUID]) -> None:
        """ Handles submit request by validating and propagating the result

        :param params: a dict containing a valid uui4 hex as `job_id` and a valid block nonce as `nonce`
        :type params: Dict

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        if "job_id" not in params or "nonce" not in params:
            return self.send_error(INVALID_PARAMS, id, {"params": params, "required": ["job_id", "nonce"]})

        if not valid_uuid(params["job_id"]):
            return self.send_error(INVALID_PARAMS, id, {
                "job_id": params["job_id"],
                "message": "job_id is invalid uuid4"
            })

        job_id = UUID(params["job_id"])
        job = self.jobs.get(job_id)

        if job is None:
            return self.send_error(JOB_NOT_FOUND, id, {
                "current_job": self.current_job and self.current_job.id.hex,
                "job_id": job_id.hex
            })

        # It may take a while for pubsub to get a new job.
        # To avoid propdagating the same block multiple times, we check if it has been already submitted.
        if job is not self.current_job or job.submitted:
            return self.send_error(STALE_JOB, id, {
                "current_job": self.current_job and self.current_job.id.hex,
                "job_id": job_id.hex
            })

        block = job.block.clone()
        # Stratum sends the nonce as a big-endian hexadecimal string.
        block.nonce = int(params["nonce"], 16)
        block.update_hash()
        assert block.hash is not None

        try:
            block.verify_pow()
        except PowError:
            return self.send_error(INVALID_SOLUTION, id, {
                "hash": block.hash.hex(),
                "target": int(block.get_target()).to_bytes(32, 'big').hex()
            })

        try:
            self.manager.propagate_tx(block, fails_silently=False)
        except (InvalidNewTransaction, TxValidationError) as e:
            return self.send_error(PROPAGATION_FAILED, id, {"exception": str(e)})

        print('BLOCK PARENT', block.parents[0].hex())
        job.submitted = True
        self.send_result("ok", id)

    def job_request(self, job: ServerJob) -> None:
        """ Sends a job request to the connected client

        :param job: data representing the mining job
        :type job: ServerJob
        """
        self.current_job = job
        self.jobs[job.id] = job

        self.job_queue.put(job.id)
        if self.job_queue.qsize() > self.JOBS_HISTORY:
            job_id = self.job_queue.get()
            self.jobs.pop(job_id)

        self.send_request("job", {
            "data": job.block.get_header_without_nonce().hex(),
            "job_id": job.id.hex,
            "nonce_size": Block.NONCE_SIZE,
            "weight": float(job.block.weight),
        })


class StratumFactory(Factory):
    """
    Twisted factory of server Hathor Stratum protocols.
    Interfaces with nodes to keep mining jobs up to date and to submit successful ones.
    """

    reactor: IReactorTCP
    jobs: Set[UUID]
    manager: "HathorManager"
    miner_protocols: Dict[UUID, StratumProtocol]
    port: int

    log: ClassVar[Logger] = Logger()

    def __init__(self, manager: "HathorManager", port: int, reactor: IReactorTCP = reactor):
        self.manager = manager
        self.port = port
        self.reactor = reactor

        self.jobs = set()
        self.miner_protocols = {}

    def buildProtocol(self, addr: IAddress) -> StratumProtocol:
        protocol = StratumProtocol(self, self.manager, addr)
        return protocol

    def create_job(self, miner: UUID, address: Optional[bytes] = None) -> ServerJob:
        """
        Creates a job for the designated miner.

        :param miner: id of the job miner
        :type miner: UUID

        :return: created job
        :rtype: ServerJob
        """
        id = uuid4()
        self.jobs.add(id)

        peer_id = self.manager.my_peer.id
        assert peer_id is not None

        # Only get first 32 bytes of peer_id because block data is limited to 100 bytes
        data = "{}-{}-{}".format(peer_id[:32], miner.hex, id.hex).encode()[:settings.BLOCK_DATA_MAX_SIZE]
        block = self.manager.generate_mining_block(data=data, address=address)

        return ServerJob(id, miner, block)

    def update_jobs(self) -> None:
        """
        Creates and sends a new job for each subscribed miner.
        """
        for miner, protocol in self.miner_protocols.items():
            job = self.create_job(miner, protocol.miner_address)
            protocol.job_request(job)

    def start(self) -> None:
        """
        Starts the Hathor Stratum server and subscribes for new blocks on the network in order to update miner jobs.
        """
        def on_new_block(event: HathorEvents, args: EventArguments) -> None:
            tx = args.__dict__["tx"]
            if isinstance(tx, Block):
                self.update_jobs()

        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, on_new_block)
        self.reactor.listenTCP(self.port, self)


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
        self.signal = Value("B")
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
        self.send_request("subscribe", {"address": self.address}, uuid4())

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], id: Optional[UUID]) -> None:
        """ Handles job requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: Hathor Stratum job request params
        :type params: Dict

        :param id: JSON-RPC 2.0 message id
        :type id: Optional[UUID]
        """
        self.log.debug("REQUEST {method} WITH PARAMS {params}", method=method, params=params)

        if method == "job" and isinstance(params, dict):
            self.job = params
            self.signal.value = self.SLEEP
            self.job_data.update_job(params)
            self.signal.value = self.WORK

    def handle_result(self, result: Any, id: Optional[UUID]) -> None:
        """ Logs any result since there are not supposed to be any """
        self.log.debug("RESULT {}".format(result))

    def handle_error(self, error: Dict, data: Any, id: Optional[UUID]) -> None:
        """ Logs any error since there are not supposed to be any """
        self.log.info("ERROR {} DATA {}".format(error, data))


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
            hash.update(nonce.to_bytes(nonce_size, "big"))
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
        if data.job_id == client.job["job_id"]:
            client.log.info("Submiting job: {}".format(data))
            client.send_request("submit", data._asdict(), uuid4())
