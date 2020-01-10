from itertools import count
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple, Union, cast
from uuid import uuid4

from structlog import get_logger
from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.interfaces import IAddress, IReactorTCP
from twisted.internet.protocol import Factory
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.merged_mining.bitcoin import (
    BitcoinBlock,
    BitcoinBlockHeader,
    BitcoinTransaction,
    BitcoinTransactionInput,
    BitcoinTransactionOutput,
    build_merkle_path_for_coinbase,
    build_merkle_root_from_path,
    encode_uint32,
    encode_varint,
)
from hathor.merged_mining.bitcoin_rpc import IBitcoinRPC
from hathor.stratum import INVALID_ADDRESS, INVALID_PARAMS, JOB_NOT_FOUND, JSONRPC, METHOD_NOT_FOUND
from hathor.transaction import BitcoinAuxPow
from hathor.transaction.exceptions import ScriptError
from hathor.util import ichunks
from hathor.wallet.exceptions import InvalidAddress

logger = get_logger()
settings = HathorSettings()


MAGIC_NUMBER = b'Hath'  # bytes.fromhex('48617468') or 0x68746148.to_bytes(4, 'little')


class HathorCoordJob(NamedTuple):
    """ Data class used to send a job's work to Hathor Stratum.
    """
    data: bytes
    job_id: bytes
    nonce_size: int
    weight: float
    parent_hash: bytes

    @classmethod
    def from_dict(cls, params: dict) -> 'HathorCoordJob':
        """ Build instance from dict (received from Hathor stratum).
        """
        return cls(
            bytes.fromhex(params['data']),
            bytes.fromhex(params['job_id']),
            int(params['nonce_size']),
            float(params['weight']),
            bytes.fromhex(params['parent_hash']),  # TODO: if paremeter is not present, it is not a block
        )


class HathorStratumClient(JSONRPC):
    """ Twisted protocol that implements client side of Hathor Stratum.
    """

    coordinator: 'MergedMiningCoordinator'
    address: str

    def __init__(
            self,
            coordinator: 'MergedMiningCoordinator',
            address: str,
            id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count(),
    ):
        self.log = logger.new(address=address)
        self.coordinator = coordinator
        self.address = address
        self._iter_id = id_generator and id_generator() or None
        self._subscribed = False
        self._subscribe_msg_id = None

    def _next_id(self):
        if self._iter_id:
            return str(next(self._iter_id))

    def connectionMade(self) -> None:
        self.log.debug('connection made')
        self.ensure_subscribed()

    def ensure_subscribed(self) -> None:
        if self._subscribed:
            return
        self.log.debug('not subscribed, subscribing...')
        if self._subscribe_msg_id is not None:
            # TODO: timeout?
            self.log.debug('already waiting for subcribe response')
            return
        self._subscribe_msg_id = self._next_id()
        self.send_request('subscribe', {'address': self.address, 'merged_mining': True}, self._subscribe_msg_id)

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str]) -> None:
        """ Handles job requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: Hathor Stratum job request params
        :type params: Dict

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.ensure_subscribed()
        self.log.debug('handle request', method=method, params=params)

        if method == 'job' and isinstance(params, dict):
            self.coordinator.hathor_coord_job = HathorCoordJob.from_dict(params)
            self.coordinator.update_merged_block()
        else:
            self.log.error('Unknown method received, ignoring', method=method)

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any.
        """
        self.log.debug('handle result', msgid=msgid, result=result)
        if not self._subscribed:
            if msgid == self._subscribe_msg_id:
                self._subscribed = True
                self.log.debug('subscribed')

    def handle_error(self, error: Dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any error since there are not supposed to be any.
        """
        self.log.error('handle error', msgid=msgid, error=error)
        if not self._subscribed:
            if msgid == self._subscribe_msg_id:
                self._subscribe_msg_id = None
                self.log.debug('subscribe failed')


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


TRUE_DIFF_ONE = int(0x00000000ffff0000000000000000000000000000000000000000000000000000)


def diff_from_weight(weight: float) -> int:
    """ Convert Hathor block weight to Bitcoin block difficulty.
    """
    cut = int(2**(256 - weight) - 1)
    diff = TRUE_DIFF_ONE // cut
    # TODO: does rounding up make sense? cgminer does it
    diff = max(diff, 1)
    return diff


class SingleMinerWork(NamedTuple):
    """ Work submitted by a miner, result from a SingleMinerJob.
    """

    job_id: str
    nonce: int
    xnonce1: bytes  # not submitted by miner
    xnonce2: bytes
    timestamp: Optional[int] = None

    @classmethod
    def from_stratum_params(cls, xnonce1: bytes, params: List) -> 'SingleMinerWork':
        from hathor.merged_mining.bitcoin import read_uint32
        _rpc_user, job_id, raw_xnonce2, raw_timestamp, raw_nonce = params
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
    merkle_path: List[bytes]
    version: int
    bits: bytes  # 4 bytes
    timestamp: int
    hathor_data: bytes
    hathor_job_id: bytes
    transactions: List[BitcoinTransaction]
    clean: bool = True

    def to_stratum_params(self) -> List:
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
            encode_uint32(self.timestamp)[::-1].hex(),  # FIXME/TODO: verify actual endianess
            self.clean
        ]

    def _make_coinbase(self, work: SingleMinerWork) -> BitcoinTransaction:
        """ Assemble the Bitcoin coinbase transaction from this job and a given work.
        """
        return BitcoinTransaction.decode(b''.join([self.coinbase_head, work.xnonce, self.coinbase_tail]))

    def _make_bitcoin_block_and_coinbase(self, work: SingleMinerWork) -> Tuple[BitcoinBlockHeader, BitcoinTransaction]:
        """ Assemble the Bitcoin block header and coinbase transaction from this job and a given work.
        """
        coinbase_tx = self._make_coinbase(work)
        bitcoin_header = BitcoinBlockHeader(
            self.version,
            self.prev_hash,
            build_merkle_root_from_path([coinbase_tx.hash] + self.merkle_path),
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
        from hathor.merged_mining.bitcoin import sha256d_hash
        bitcoin_header, coinbase_tx = self._make_bitcoin_block_and_coinbase(work)
        header = bytes(bitcoin_header)
        header_head, header_tail = header[:36], header[-12:]
        block_base_hash = sha256d_hash(self.hathor_data)
        coinbase = bytes(coinbase_tx)
        coinbase_head, coinbase_tail = coinbase.split(block_base_hash)
        return BitcoinAuxPow(header_head, coinbase_head, coinbase_tail, self.merkle_path, header_tail)

    def build_bitcoin_block(self, work: SingleMinerWork) -> BitcoinBlock:
        """ Build the Bitcoin Block from job and work data.
        """
        bitcoin_header, coinbase_tx = self._make_bitcoin_block_and_coinbase(work)
        bitcoin_block = BitcoinBlock(bitcoin_header, [coinbase_tx] + self.transactions[:])
        return bitcoin_block


class MergedMiningStratumProtocol(JSONRPC):
    """
    Twisted protocol that implements server side of the merged mining coordinator.
    """

    DEFAULT_XNONCE2_SIZE = 8

    merged_job: 'MergedJob'

    def __init__(self, coordinator: 'MergedMiningCoordinator', address: IAddress, xnonce1: bytes = b'',
                 job_id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count()):
        self.log = logger.new(address=address)
        self.coordinator = coordinator
        self.address = address

        self.current_job = None
        self.jobs: Dict[str, SingleMinerJob] = {}
        self.miner_id: Optional[str] = None
        self.miner_address: Optional[bytes] = None
        self.job_ids: List[str] = []
        # TODO: maybe try to guess min_difficulty from the miner
        # TODO: parametrize this
        self.min_difficulty = 4096
        self.last_sent_difficulty: Optional[int] = None

        self.xnonce1 = xnonce1
        self.xnonce2_size = self.DEFAULT_XNONCE2_SIZE

        self._iter_job_id = job_id_generator and job_id_generator() or None
        self.subscribed = False

    def next_job_id(self):
        if self._iter_job_id:
            return str(next(self._iter_job_id))
        return str(uuid4())

    def connectionMade(self) -> None:
        self.miner_id = str(uuid4())
        self.coordinator.miner_protocols[self.miner_id] = self
        self.log = self.log.bind(miner_id=self.miner_id)
        self.log.debug('connection made')

    def connectionLost(self, reason: Failure = None) -> None:
        self.log.debug('connection lost')
        if self.subscribed:
            self.log.info('Miner exited')
        assert self.miner_id is not None
        self.coordinator.miner_protocols.pop(self.miner_id)

    def handle_request(self, method: str, params: Optional[Union[List, Dict]], msgid: Optional[str]) -> None:
        """ Handles subscribe and submit requests.

        :param method: JSON-RPC 2.0 request method
        :type method: str

        :param params: JSON-RPC 2.0 request params
        :type params: Optional[Union[List, Dict]]

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        self.log.debug('handle request', method=method, params=params)

        if method in {'subscribe', 'mining.subscribe', 'login'}:
            params = cast(Dict, params)
            return self.handle_subscribe(params, msgid)
        if method in {'authorize', 'mining.authorize'}:
            params = cast(Dict, params)
            return self.handle_authorize(params, msgid)
        if method in {'submit', 'mining.submit'}:
            params = cast(List, params)
            return self.handle_submit(params, msgid)
        if method in {'configure', 'mining.configure'}:
            params = cast(List, params)
            return self.handle_configure(params, msgid)

        self.send_error(METHOD_NOT_FOUND, msgid, data={'method': method, 'supported_methods': ['submit', 'subscribe']})

    def handle_result(self, result: Any, msgid: Optional[str]) -> None:
        """ Logs any result since there are not supposed to be any.
        """
        self.log.debug('handle result', msgid=msgid, result=result)

    def handle_error(self, error: Dict, data: Any, msgid: Optional[str]) -> None:
        """ Logs any errors since there are not supposed to be any.
        """
        self.log.error('handle error', msgid=msgid, error=error)

    def handle_authorize(self, params: Dict, msgid: Optional[str]) -> None:
        """ Handles authorize request by always authorizing even if the request is invalid.
        """
        # TODO: authorization system
        self.send_result('ok', msgid)

    def handle_configure(self, params: List, msgid: Optional[str]) -> None:
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

    def handle_subscribe(self, params: Dict, msgid: Optional[str]) -> None:
        """ Handles subscribe request by answering it and triggering a job request.

        :param msgid: JSON-RPC 2.0 message id
        :type msgid: Optional[str]
        """
        assert self.miner_id is not None
        if params and 'address' in params and params['address'] is not None:
            try:
                self.miner_address = decode_address(params['address'])
            except InvalidAddress:
                self.send_error(INVALID_ADDRESS, msgid)
                self.transport.loseConnection()
                return

        self.subscribed = True
        self.log.info('Miner subscribed', address=self.miner_address)
        self.send_result([str(self.miner_id), self.xnonce1.hex(), self.xnonce2_size], msgid)
        # self.job_request()  # waiting for the next update is better

    def handle_submit(self, params: List[Any], msgid: Optional[str]) -> None:
        """ Handles submit request by validating and propagating the result

        - params: rpc_user, job_id, xnonce2, time, nonce

        Example:

        - ['', '6a16cffa-47c0-41d9-b92f-44e05d3c25dd', '0000000000000000', 'c359f65c', '47c8f488']
        """
        from hathor.merged_mining.bitcoin import sha256d_hash

        self.log.debug('handle submit', msgid=msgid, params=params)

        work = SingleMinerWork.from_stratum_params(self.xnonce1, params)

        job = self.jobs.get(work.job_id)
        if not job:
            self.log.error('job not found', job_id=work.job_id)
            return

        bitcoin_block_header = job.build_bitcoin_block_header(work)
        block_base = job.hathor_data
        block_base_hash = sha256d_hash(block_base)
        self.log.debug('work received', bitcoin_header=bytes(bitcoin_block_header).hex(),
                       block_base=block_base.hex(), block_base_hash=block_base_hash.hex(),
                       hash=bitcoin_block_header.hash.hex())

        aux_pow = job.build_aux_pow(work)
        aux_pow.verify(block_base_hash)  # TODO: treat exception (respond with proper error)

        self.log.debug('forward work to hathor', aux_pow=aux_pow)
        self.submit_to_hathor(job, aux_pow)

        # XXX: work is always sent to bitcoin node, which rejects accordingly
        self.log.debug('forward work to bitcoin', work=work)
        self.submit_to_bitcoin(job, work)

        # TODO: don't always return success?
        self.send_result(True, msgid)

    def submit_to_hathor(self, job: SingleMinerJob, aux_pow: BitcoinAuxPow) -> None:
        """ Submit AuxPOW to Hathor stratum.
        """
        from hathor.stratum.stratum import MinerSubmit as HathorMinerSubmit
        data = HathorMinerSubmit(job.hathor_job_id.hex(), aux_pow=bytes(aux_pow).hex())
        hathor_stratum = self.coordinator.hathor_stratum
        hathor_stratum.send_request('submit', data._asdict(), str(hathor_stratum._next_id()))

    def submit_to_bitcoin(self, job: SingleMinerJob, work: SingleMinerWork) -> None:
        """ Submit work to Bitcoin RPC.
        """
        bitcoin_rpc = self.coordinator.bitcoin_rpc
        bitcoin_block = job.build_bitcoin_block(work)
        data = bytes(bitcoin_block)
        # TODO: handle RPC response
        d = bitcoin_rpc.submit_block(data)
        d.addCallback(self._cb_submit_to_bitcoin)
        d.addErrback(print)  # TODO: better error handling

    def _cb_submit_to_bitcoin(self, data: dict) -> None:
        """ Callback used for the async call on submit_to_bitcoin.
        """
        self.log.info('Bitcoin RPC submit response', data=data)

    def estimate_difficulty(self) -> int:
        """ Value to send through mining.set_difficulty.

        Depends on the difficulty of the Hathor job and Bitcoin job.
        """
        # XXX: we assume bitcoin difficulty is higher than ours, which will be true for the foreseeable future
        assert self.coordinator.hathor_coord_job is not None
        difficulty = diff_from_weight(self.coordinator.hathor_coord_job.weight)
        difficulty = max(difficulty, self.min_difficulty)
        return difficulty

    def set_difficulty(self) -> None:
        """ Sends the difficulty to the connected client, applies for all future "mining.notify" until it is set again.
        """
        diff = self.estimate_difficulty()
        if diff != self.last_sent_difficulty:
            self.last_sent_difficulty = diff
            self.send_request('mining.set_difficulty', [diff])

    def job_request(self) -> None:
        """ Sends a job request to the connected client.
        """
        if not self.coordinator.merged_job:
            self.send_error(JOB_NOT_FOUND, data={'message': 'Not ready to give a job.'})
            return

        try:
            job = self.coordinator.merged_job.new_single_miner_job(self)
        except (ValueError, ScriptError) as e:
            # ScriptError might happen if try to use a mainnet address in the testnet or vice versa
            # ValueError happens if address is not a valid base58 address
            self.send_error(INVALID_PARAMS, data={'message': str(e)})
        else:
            self.jobs[job.job_id] = job

            self.set_difficulty()
            self.send_request('mining.notify', job.to_stratum_params())

            # for debugging only:
            bitcoin_block = job.build_bitcoin_block_header(self.dummy_work(job))
            self.log.debug('job updated', bitcoin_block=bytes(bitcoin_block).hex(),
                           merkle_root=bitcoin_block.merkle_root.hex())

    def dummy_work(self, job: SingleMinerJob) -> SingleMinerWork:
        """ Useful only for debugging.
        """
        return SingleMinerWork(job.job_id, 0, self.xnonce1, b'\0' * self.xnonce2_size)


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
    transactions: List[BitcoinTransaction]

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
        return cls(
            params['version'],
            bytes.fromhex(params['previousblockhash']),
            params['coinbasevalue'],
            bytes.fromhex(params['target']),
            params['mintime'],
            params['sizelimit'],
            bytes.fromhex(params['bits']),
            params['height'],
            list(map(BitcoinTransaction.from_dict, params['transactions'])),
        )

    def make_coinbase_transaction(self, hathor_block_hash: bytes, payback_address_bitcoin: str,
                                  extra_nonce_size: Optional[int] = None) -> BitcoinTransaction:
        """ The coinbase transaction is entirely defined by the coordinator, which acts as a pool server.
        """
        inputs = []
        outputs: List[BitcoinTransactionOutput] = []

        # coinbase input
        coinbase_script = encode_varint(self.height)

        # add hathor base block hash to coinbase:
        coinbase_script += MAGIC_NUMBER
        coinbase_script += hathor_block_hash

        if extra_nonce_size is not None:
            coinbase_script += b'\0' * extra_nonce_size

        coinbase_input = BitcoinTransactionInput.coinbase(coinbase_script)
        inputs.append(coinbase_input)

        # coinbase output: payout
        # TODO

        return BitcoinTransaction(inputs=inputs, outputs=outputs)

    def get_timestamp(self) -> int:
        """ Timestamp is now or min_time, whatever is higher."""
        from datetime import datetime
        return max(int(datetime.now().timestamp()), self.min_time)


class MergedJob(NamedTuple):
    """ Current merged job, of which 'single miner jobs' may fullfill the work for either coin.
    """

    hathor_coord: HathorCoordJob
    bitcoin_coord: BitcoinCoordJob
    payback_address_bitcoin: str
    clean: bool

    def new_single_miner_job(self, protocol: MergedMiningStratumProtocol) -> SingleMinerJob:
        """ Generate a partial job for a single miner, based on this job.
        """
        from hathor.merged_mining.bitcoin import sha256d_hash

        # payback_address_bitcoin = protocol.coordinator.payback_address_bitcoin
        xnonce_size = len(protocol.xnonce1) + protocol.xnonce2_size

        # base txs for merkle tree, before coinbase
        transactions = self.bitcoin_coord.transactions[:]

        # build coinbase transaction with hathor block hash
        hathor_block_hash = sha256d_hash(self.hathor_coord.data)
        coinbase_tx = self.bitcoin_coord.make_coinbase_transaction(
            hathor_block_hash,
            self.payback_address_bitcoin,
            xnonce_size,
        )
        coinbase_bytes = bytes(coinbase_tx)
        coinbase_head, coinbase_tail = coinbase_bytes.split(hathor_block_hash + b'\0' * xnonce_size, 1)
        coinbase_head += hathor_block_hash
        assert len(coinbase_bytes) == len(coinbase_head) + xnonce_size + len(coinbase_tail)  # just a sanity check

        # TODO: check if total transaction size increase exceed size and sigop limits, there's probably an RPC for this

        return SingleMinerJob(
            job_id=protocol.next_job_id(),
            prev_hash=self.bitcoin_coord.previous_block_hash,
            coinbase_head=coinbase_head,
            coinbase_tail=coinbase_tail,
            merkle_path=build_merkle_path_for_coinbase([tx.hash for tx in transactions]),
            version=self.bitcoin_coord.version,
            bits=self.bitcoin_coord.bits,
            hathor_data=self.hathor_coord.data,
            hathor_job_id=self.hathor_coord.job_id,
            timestamp=self.bitcoin_coord.get_timestamp(),
            transactions=transactions,
            clean=self.clean,
        )


class MergedMiningCoordinator(Factory):
    """
    Twisted factory of server Hathor Stratum protocols.
    Interfaces with nodes to keep mining jobs up to date and to submit successful ones.

    xnonce1: set by the server, used to prevent miners work from overlapping
    xnonce2: set by the client, server only sets the size (defaults to 8 bytes), bigger search space
    """

    COORDINATOR_LOOP_INTERVAL = 0.3
    WATCHDOG_LOOP_INTERVAL = 30.0
    XNONCE1_SIZE = 2
    MAX_XNONCE1 = 2**XNONCE1_SIZE - 1

    def __init__(self, port: int, bitcoin_rpc: IBitcoinRPC, hathor_stratum: str, payback_address_bitcoin: str,
                 payback_address_hathor: str, reactor: IReactorTCP = reactor):
        self.log = logger.new()
        self.port = port
        self.reactor = reactor
        self.bitcoin_rpc = bitcoin_rpc
        self._hathor_stratum_url = hathor_stratum
        self.hathor_stratum = HathorStratumClient(self, address=payback_address_hathor)
        self.jobs: Set[SingleMinerJob] = set()
        self.miner_protocols: Dict[str, MergedMiningStratumProtocol] = {}
        self.payback_address_bitcoin = payback_address_bitcoin
        self.bitcoin_coord_job: Optional[BitcoinCoordJob] = None
        self.hathor_coord_job: Optional[HathorCoordJob] = None
        self.coordinator_loop: Optional[task.LoopingCall] = None
        self.watchdog_loop: Optional[task.LoopingCall] = None
        self.merged_job: Optional[MergedJob] = None
        self._next_xnonce1 = 0
        self.job_count = 0

    def next_xnonce1(self) -> bytes:
        xnonce1 = self._next_xnonce1
        self._next_xnonce1 += 1
        if self._next_xnonce1 > self.MAX_XNONCE1:
            self._next_xnonce1 = 0
        return xnonce1.to_bytes(self.XNONCE1_SIZE, 'big')

    def buildProtocol(self, addr: IAddress) -> MergedMiningStratumProtocol:
        return MergedMiningStratumProtocol(self, addr, self.next_xnonce1())

    def update_jobs(self) -> None:
        """ Creates and sends a new job for each subscribed miner.
        """
        self.merged_job = self.next_merged_job
        for miner, protocol in self.miner_protocols.items():
            if protocol.subscribed:
                protocol.job_request()

    def start(self) -> None:
        """ Starts the coordinator and subscribes for new blocks on the both networks in order to update miner jobs.
        """
        self.reactor.listenTCP(self.port, self)
        self.start_watchdog_block_updater()
        self.start_hathor_block_updater()

    def stop(self) -> None:
        """ Stops the client, interrupting mining processes, stoping supervisor loop , and sending finished jobs.
        """
        if self.coordinator_loop:
            self.coordinator_loop.stop()
        if self.watchdog_loop:
            self.watchdog_loop.stop()

    def start_watchdog_block_updater(self) -> None:
        """ Start Bitcoin RPC client which periodically updates blocks and also make sure the Hathor connection is up.
        """
        self.log.info('Start updating Bitcoin mining block')
        self.watchdog_loop = task.LoopingCall(watchdog_loop, self)
        self.watchdog_loop.clock = self.reactor
        self.watchdog_loop.start(self.WATCHDOG_LOOP_INTERVAL)

    def start_hathor_block_updater(self) -> None:
        """ Start Hathor stratum client which periodically updates blocks.
        """
        self.log.info('Start updating Hathor mining block')
        host, port = self._hathor_stratum_url.split(':')  # TODO: improve url/address parsing
        # TODO: consider using a factory, like: reactor.connectTCP(host, port, EchoClientFactory())
        point = TCP4ClientEndpoint(self.reactor, host, int(port))
        d = connectProtocol(point, self.hathor_stratum)
        # retries if connection fails
        d.addErrback(self._err_start_hathor_block_updater)
        # TODO: monitor connection to retry if connection is interrupted after success

    def _err_start_hathor_block_updater(self, *args: Any, **kwargs: Any) -> None:
        """ Errback used for the async call on start_hathor_block_updater.
        """
        self.log.error('failed to connect to Hathor stratum, retrying in 10s.', args=args, kwargs=kwargs)
        self.reactor.callLater(10.0, self.start_hathor_block_updater)

    def update_bitcoin_block(self) -> None:
        """ Method periodically called to update the bitcoin block template.
        """
        self.log.debug('Update Bitcoin mining block')
        d = self.bitcoin_rpc.get_block_template()
        d.addCallback(self._cb_update_bitcoin_block)
        d.addErrback(self.log.error)  # TODO: better error handling, maybe also retry

    def _cb_update_bitcoin_block(self, data: dict) -> None:
        """ Callback used for the async call on update_bitcoin_block.
        """
        data_log = data.copy()
        data_log['len(transactions)'] = len(data_log['transactions'])
        del data_log['transactions']
        self.log.debug('getblocktemplate response', res=data_log)
        self.bitcoin_coord_job = BitcoinCoordJob.from_dict(data)
        self.log.debug('New Bitcoin Block template.')
        self.update_merged_block()

    def is_next_job_clean(self) -> bool:
        """ Used to determine if the current job must be immediatly stopped in favor of the next job.
        """
        assert self.bitcoin_coord_job is not None
        assert self.hathor_coord_job is not None
        if self.merged_job is None or self.merged_job.bitcoin_coord is None or self.merged_job.hathor_coord is None:
            return True
        if self.merged_job.bitcoin_coord.height != self.bitcoin_coord_job.height:
            return True
        if self.merged_job.hathor_coord.parent_hash != self.hathor_coord_job.parent_hash:
            return True
        return False

    def update_merged_block(self) -> None:
        if self.bitcoin_coord_job is None or self.hathor_coord_job is None:
            self.log.debug('Merged block not ready to be built.')
            return
        self.job_count += 1
        if self.job_count == 1:
            self.log.info('Merged mining ready')
        self.next_merged_job = MergedJob(
            self.hathor_coord_job,
            self.bitcoin_coord_job,
            self.payback_address_bitcoin,
            self.is_next_job_clean(),
        )
        self.update_jobs()
        self.log.debug('Merged job updated.')


def watchdog_loop(coordinator: MergedMiningCoordinator) -> None:
    """ Job to be executed periodically to submit complete mining jobs.
    """
    coordinator.update_bitcoin_block()
    if coordinator.hathor_stratum.connected:
        coordinator.hathor_stratum.ensure_subscribed()
