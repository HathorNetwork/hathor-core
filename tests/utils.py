import base64
import random
import subprocess
import time
import urllib.parse
from collections import deque
from concurrent import futures
from typing import TYPE_CHECKING, List

import grpc
import numpy.random
import requests
from OpenSSL.crypto import X509
from twisted.internet.task import Clock
from twisted.test import proto_helpers

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_private_key_from_bytes
from hathor.manager import HathorEvents, HathorManager
from hathor.p2p.utils import generate_certificate
from hathor.transaction import Transaction, TxInput, TxOutput, genesis
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import (
    TransactionMemoryStorage,
    TransactionRemoteStorage,
    create_transaction_storage_server,
)
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.util import get_deposit_amount

if TYPE_CHECKING:
    from hathor.p2p.peer_id import PeerId

settings = HathorSettings()

MIN_TIMESTAMP = genesis.GENESIS[-1].timestamp + 1

# useful for adding blocks to a different wallet
BURN_ADDRESS = bytes.fromhex('28acbfb94571417423c1ed66f706730c4aea516ac5762cccb8')


def resolve_block_bytes(block_bytes):
    """ From block bytes we create a block and resolve pow
        Return block bytes with hash and nonce after pow
        :rtype: bytes
    """
    from hathor.transaction import Block
    import base64
    block_bytes = base64.b64decode(block_bytes)
    block = Block.create_from_struct(block_bytes)
    block.resolve()
    return block.get_struct()


def gen_new_double_spending(manager: HathorManager, *, use_same_parents: bool = False) -> Transaction:
    tx_interval = random.choice(list(manager.tx_storage.get_tx_tips()))
    tx = manager.tx_storage.get_transaction(tx_interval.data)
    txin = random.choice(tx.inputs)

    from hathor.transaction.scripts import P2PKH, parse_address_script
    spent_tx = tx.get_spent_tx(txin)
    spent_txout = spent_tx.outputs[txin.index]
    p2pkh = parse_address_script(spent_txout.script)
    assert isinstance(p2pkh, P2PKH)

    from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
    value = spent_txout.value
    private_key = manager.wallet.get_private_key(p2pkh.address)
    inputs = [WalletInputInfo(tx_id=txin.tx_id, index=txin.index, private_key=private_key)]

    address = manager.wallet.get_unused_address(mark_as_used=True)
    outputs = [WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)]

    tx2 = manager.wallet.prepare_transaction(Transaction, inputs, outputs, manager.tx_storage)
    tx2.storage = manager.tx_storage
    tx2.weight = 1
    tx2.timestamp = max(tx.timestamp + 1, int(manager.reactor.seconds()))

    if use_same_parents:
        tx2.parents = list(tx.parents)
    else:
        tx2.parents = manager.get_new_tx_parents(tx2.timestamp)

    tx2.resolve()
    return tx2


def add_new_double_spending(manager: HathorManager, *, use_same_parents: bool = False) -> Transaction:
    tx = gen_new_double_spending(manager, use_same_parents=use_same_parents)
    manager.propagate_tx(tx, fails_silently=False)
    return tx


def gen_new_tx(manager, address, value, verify=True):
    from hathor.transaction import Transaction
    from hathor.wallet.base_wallet import WalletOutputInfo

    outputs = []
    outputs.append(WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

    tx = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs)
    tx.storage = manager.tx_storage

    max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
    tx.timestamp = max(max_ts_spent_tx + 1, int(manager.reactor.seconds()))

    tx.weight = 1
    tx.parents = manager.get_new_tx_parents(tx.timestamp)
    tx.resolve()
    if verify:
        tx.verify()
    return tx


def add_new_tx(manager, address, value, advance_clock=None):
    """ Create, resolve and propagate a new tx

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :param address: Address of the output
        :type address: str

        :param value: Value of the output
        :type value: int

        :return: Transaction created
        :rtype: :py:class:`hathor.transaction.transaction.Transaction`
    """
    tx = gen_new_tx(manager, address, value)
    manager.propagate_tx(tx, fails_silently=False)
    if advance_clock:
        manager.reactor.advance(advance_clock)
    return tx


def add_new_transactions(manager, num_txs, advance_clock=None):
    """ Create, resolve and propagate some transactions

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :param num_txs: Quantity of txs to be created
        :type num_txs: int

        :return: Transactions created
        :rtype: List[Transaction]
    """
    txs = []
    for _ in range(num_txs):
        address = 'HGov979VaeyMQ92ubYcnVooP6qPzUJU8Ro'
        value = random.choice([5, 10, 15, 20])
        tx = add_new_tx(manager, address, value, advance_clock)
        txs.append(tx)
    return txs


def add_new_block(manager, advance_clock=None, *, parent_block_hash=None, data=b'', weight=None, address=None):
    """ Create, resolve and propagate a new block

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :return: Block created
        :rtype: :py:class:`hathor.transaction.block.Block`
    """
    block = manager.generate_mining_block(parent_block_hash=parent_block_hash, data=data, address=address)
    if weight is not None:
        block.weight = weight
    block.resolve()
    block.verify()
    manager.propagate_tx(block, fails_silently=False)
    if advance_clock:
        manager.reactor.advance(advance_clock)
    return block


def add_new_blocks(manager, num_blocks, advance_clock=None, *, parent_block_hash=None,
                   block_data=b'', weight=None, address=None):
    """ Create, resolve and propagate some blocks

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :param num_blocks: Quantity of blocks to be created
        :type num_blocks: int

        :return: Blocks created
        :rtype: List[Block]
    """
    blocks = []
    for _ in range(num_blocks):
        blocks.append(
            add_new_block(manager, advance_clock, parent_block_hash=parent_block_hash,
                          data=block_data, weight=weight, address=address)
        )
        if parent_block_hash:
            parent_block_hash = blocks[-1].hash
    return blocks


def add_blocks_unlock_reward(manager):
    """This method adds new blocks to a 'burn address' to make sure the existing
    block rewards can be spent. It uses a 'burn address' so the manager's wallet
    is not impacted.
    """
    return add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1, address=BURN_ADDRESS)


class HathorStringTransport(proto_helpers.StringTransport):
    def __init__(self, peer: 'PeerId'):
        self.peer = peer
        super().__init__()

    def getPeerCertificate(self) -> X509:
        certificate = generate_certificate(self.peer.private_key, settings.CA_FILEPATH, settings.CA_KEY_FILEPATH)
        openssl_certificate = X509.from_cryptography(certificate)
        return openssl_certificate


class FakeConnection:
    def __init__(self, manager1, manager2, *, latency: float = 0):
        """
        :param: latency: Latency between nodes in seconds
        """
        self.manager1 = manager1
        self.manager2 = manager2

        self.latency = latency
        self.is_connected = True

        self._proto1 = manager1.server_factory.buildProtocol(('127.0.0.1', 0))
        self._proto2 = manager2.client_factory.buildProtocol(('127.0.0.1', 0))

        self.tr1 = HathorStringTransport(self._proto2.my_peer)
        self.tr2 = HathorStringTransport(self._proto1.my_peer)

        self._do_buffering = True
        self._buf1 = deque()
        self._buf2 = deque()

        self._proto1.makeConnection(self.tr1)
        self._proto2.makeConnection(self.tr2)

    @property
    def proto1(self):
        return self._proto1

    @property
    def proto2(self):
        return self._proto2

    def run_one_step(self, debug=False, force=False):
        assert self.is_connected, 'not connected'

        if debug:
            print('[do step]')

        if self._do_buffering:
            if not self._buf1:
                self._buf1.extend(self.tr1.value().splitlines(keepends=True))
                self.tr1.clear()
            if not self._buf2:
                self._buf2.extend(self.tr2.value().splitlines(keepends=True))
                self.tr2.clear()
            if self._buf1:
                line1 = self._buf1.popleft()
            else:
                line1 = b''
            if self._buf2:
                line2 = self._buf2.popleft()
            else:
                line2 = b''
        else:
            line1 = self.tr1.value()
            self.tr1.clear()
            line2 = self.tr2.value()
            self.tr2.clear()

        if line1:
            if self.latency > 0:
                self.manager1.reactor.callLater(self.latency, self._deliver_message, self._proto2, line1, debug)
                if debug:
                    print('[1->2] delayed by', self.latency)
            else:
                self._proto2.dataReceived(line1)
                if debug:
                    print('[1->2]', line1)

        if line2:
            if self.latency > 0:
                self.manager2.reactor.callLater(self.latency, self._deliver_message, self._proto1, line2, debug)
                if debug:
                    print('[1->2] delayed by', self.latency)
            else:
                self._proto1.dataReceived(line2)
                if debug:
                    print('[2->1]', line2)

        return True

    def run_until_complete(self, debug=False, force=False):
        while not self.is_empty():
            self.run_one_step(debug=debug, force=force)

    def _deliver_message(self, proto, data, debug=False):
        proto.dataReceived(data)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self._proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self._proto2.connectionLost(reason)
        self.is_connected = False

    def is_empty(self):
        if self._do_buffering and (self._buf1 or self._buf2):
            return False
        return not self.tr1.value() and not self.tr2.value()

    def peek_tr1_value(self):
        if self._do_buffering and self._buf1:
            return self._buf1[0]
        value = self.tr1.value()
        if not value:
            return b''
        return value.splitlines(keepends=True)[0]

    def peek_tr2_value(self):
        if self._do_buffering and self._buf2:
            return self._buf2[0]
        value = self.tr2.value()
        if not value:
            return b''
        return value.splitlines(keepends=True)[0]


class Simulator:
    def __init__(self, clock: Clock):
        self.clock = clock
        self.connections = []

    def add_connection(self, conn: FakeConnection):
        self.connections.append(conn)

    def run(self, interval: float, step: float = 0.25, status_interval: float = 60.0):
        initial = self.clock.seconds()
        latest_time = self.clock.seconds()
        t0 = time.time()
        while self.clock.seconds() <= initial + interval:
            for conn in self.connections:
                conn.run_one_step()
            if self.clock.seconds() - latest_time >= status_interval:
                t1 = time.time()
                print('[{:8.2f}][rate={:8.2f}] t={:15.2f}    dt={:8.2f}    toBeRun={:8.2f}    delayedCall={}'.format(
                    t1 - t0,
                    (self.clock.seconds() - initial) / (t1 - t0),
                    self.clock.seconds(),
                    self.clock.seconds() - initial,
                    interval - self.clock.seconds() + initial,
                    len(self.clock.getDelayedCalls()),
                ))
                latest_time = self.clock.seconds()
            self.clock.advance(step)


class MinerSimulator:
    """ Simulate block mining with actually solving the block. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(self, manager: HathorManager, *, hashpower: float):
        """
        :param: hashpower: Number of hashes per second
        """
        self.manager = manager
        self.hashpower = hashpower
        self.clock = manager.reactor
        self.block = None
        self.delayedcall = None

    def start(self) -> None:
        """ Start mining blocks.
        """
        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)
        self.schedule_next_block()

    def stop(self) -> None:
        """ Stop mining blocks.
        """
        if self.delayedcall:
            self.delayedcall.cancel()
            self.delayedcall = None
        self.manager.pubsub.unsubscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)

    def on_new_tx(self, key: HathorEvents, args):
        """ Called when a new tx or block is received. It updates the current mining to the
        new block.
        """
        tx = args.tx
        if not tx.is_block:
            return
        if not self.block:
            return

        tips = tx.storage.get_best_block_tips()
        if self.block.parents[0] not in tips:
            # Head changed
            self.block = None
            self.schedule_next_block()

    def schedule_next_block(self):
        """ Schedule the propagation of the next block, and propagate a block if it has been found.
        """
        if self.block:
            self.block.nonce = random.randrange(0, 2**32)
            self.block.update_hash()
            self.manager.propagate_tx(self.block, fails_silently=False)
            self.block = None

        block = self.manager.generate_mining_block()
        geometric_p = 2**(-block.weight)
        trials = numpy.random.geometric(geometric_p)
        dt = 1.0 * trials / self.hashpower

        self.block = block
        if self.delayedcall and self.delayedcall.active():
            self.delayedcall.cancel()
        self.delayedcall = self.clock.callLater(dt, self.schedule_next_block)


class RandomTransactionGenerator:
    """ Generates random transactions without mining. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(self, manager: HathorManager, *, rate: float, hashpower: float, ignore_no_funds: bool = False):
        """
        :param: rate: Number of transactions per second
        :param: hashpower: Number of hashes per second
        """
        self.manager = manager

        # List of addresses to send tokens. If this list is empty, tokens will be sent to an address
        # of its own wallet.
        self.send_to: List[HathorManager] = []

        self.clock = manager.reactor
        self.rate = rate
        self.hashpower = hashpower
        self.ignore_no_funds = ignore_no_funds
        self.tx = None
        self.delayedcall = None

    def start(self):
        """ Start generating random transactions.
        """
        self.schedule_next_transaction()

    def stop(self):
        """ Stop generating random transactions.
        """
        if self.delayedcall:
            self.delayedcall.cancel()
            self.delayedcall = None

    def schedule_next_transaction(self):
        """ Schedule the generation of a new transaction.
        """
        if self.tx:
            self.manager.propagate_tx(self.tx, fails_silently=False)
            self.tx = None

        dt = random.expovariate(self.rate)
        self.delayedcall = self.clock.callLater(dt, self.new_tx_step1)

    def new_tx_step1(self):
        """ Generate a new transaction and schedule the mining part of the transaction.
        """
        balance = self.manager.wallet.balance[settings.HATHOR_TOKEN_UID]
        if balance.available == 0 and self.ignore_no_funds:
            self.delayedcall = self.clock.callLater(0, self.schedule_next_transaction)
            return

        if not self.send_to:
            address = self.manager.wallet.get_unused_address(mark_as_used=False)
        else:
            address = random.choice(self.send_to)

        value = random.randint(1, balance.available)
        tx = gen_new_tx(self.manager, address, value)
        tx.timestamp = int(self.clock.seconds())
        tx.weight = self.manager.minimum_tx_weight(tx)
        tx.update_hash()

        geometric_p = 2**(-tx.weight)
        trials = numpy.random.geometric(geometric_p)
        dt = 1.0 * trials / self.hashpower

        self.tx = tx
        self.delayedcall = self.clock.callLater(dt, self.schedule_next_transaction)


def run_server(hostname='localhost', listen=8005, status=8085, bootstrap=None, tries=100):
    """ Starts a full node in a subprocess running the cli command

        :param hostname: Hostname used to be accessed by other peers
        :type hostname: str

        :param listen: Port to listen for new connections (eg: 8000)
        :type listen: int

        :param status: Port to run status server
        :type status: int

        :param bootstrap: Address to connect to (eg: tcp:127.0.0.1:8000)
        :type bootstrap: str

        :param tries: How many loop tries we will have waiting for the node to run
        :type tries: int

        :return: Subprocess created
        :rtype: :py:class:`subprocess.Popen`
    """
    command = ' '.join([
        'python -m hathor run_node',
        '--wallet hd',
        '--wallet-enable-api',
        '--hostname {}'.format(hostname),
        '--listen tcp:{}'.format(listen),
        '--status {}'.format(status),
        # We must allow mining without peers, otherwise some tests won't be able to mine.
        '--allow-mining-without-peers',
        '--wallet-index'
    ])

    if bootstrap:
        command = '{} --bootstrap {}'.format(command, bootstrap)

    process = subprocess.Popen(command.split())

    partial_url = 'http://{}:{}'.format(hostname, status)
    url = urllib.parse.urljoin(partial_url, '/wallet/balance/')
    while True:
        try:
            requests.get(url)
            break
        except requests.exceptions.ConnectionError:
            tries -= 1
            if tries == 0:
                raise TimeoutError('Error when running node for testing')
            time.sleep(0.1)

    return process


def request_server(path, method, host='http://localhost', port=8085, data=None, prefix=settings.API_VERSION_PREFIX):
    """ Execute a request for status server

        :param path: Url path of the request
        :type path: str

        :param method: Request method (eg: GET, POST, ...)
        :type method: str

        :param host: Host to execute request (eg: http://localhost)
        :type host: str

        :param port: Port to connect in the host
        :type port: int

        :param data: Request data
        :type data: Dict

        :return: Response in json format
        :rtype: Dict (json)
    """
    partial_url = '{}:{}/{}/'.format(host, port, prefix)
    url = urllib.parse.urljoin(partial_url, path)
    if method == 'GET':
        response = requests.get(url, params=data)
    elif method == 'POST':
        response = requests.post(url, json=data)
    elif method == 'PUT':
        response = requests.put(url, json=data)
    else:
        raise ValueError('Unsuported method')
    return response.json()


def execute_mining(path='mining', *, count, host='http://localhost', port=8085, data=None,
                   prefix=settings.API_VERSION_PREFIX):
    """Execute a mining on a given server"""
    from hathor.cli.mining import create_parser, execute
    partial_url = '{}:{}/{}/'.format(host, port, prefix)
    url = urllib.parse.urljoin(partial_url, path)
    parser = create_parser()
    args = parser.parse_args([url, '--count', str(count)])
    execute(args)


def execute_tx_gen(*, count, address=None, value=None, timestamp=None, host='http://localhost', port=8085, data=None,
                   prefix=settings.API_VERSION_PREFIX):
    """Execute a tx generator on a given server"""
    from hathor.cli.tx_generator import create_parser, execute
    url = '{}:{}/{}/'.format(host, port, prefix)
    parser = create_parser()
    argv = [url, '--count', str(count)]
    if address is not None:
        argv.extend(['--address', address])
    if value is not None:
        argv.extend(['--value', str(value)])
    if timestamp is not None:
        argv.extend(['--timestamp', timestamp])
    args = parser.parse_args(argv)
    execute(args)


def get_genesis_key():
    private_key_bytes = base64.b64decode(
        'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgOCgCddzDZsfKgiMJLOt97eov9RLwHeePyBIK2WPF8MChRA'
        'NCAAQ/XSOK+qniIY0F3X+lDrb55VQx5jWeBLhhzZnH6IzGVTtlAj9Ki73DVBm5+VXK400Idd6ddzS7FahBYYC7IaTl'
    )
    return get_private_key_from_bytes(private_key_bytes)


def create_tokens(manager: 'HathorManager', address_b58: str = None, mint_amount: int = 300,
                  token_name: str = 'TestCoin', token_symbol: str = 'TTC', propagate: bool = True,
                  use_genesis: bool = True):
    """Creates a new token and propagates a tx with the following UTXOs:
    0. some tokens (already mint some tokens so they can be transferred);
    1. mint authority;
    2. melt authority;
    3. deposit change;

    :param manager: hathor manager
    :type manager: :class:`hathor.manager.HathorManager`

    :param address_b58: address where tokens will be transferred to
    :type address_b58: string

    :param token_name: the token name for the new token
    :type token_name: str

    :param token_symbol: the token symbol for the new token
    :type token_symbol: str

    :param use_genesis: If True will use genesis outputs to create token, otherwise will use manager wallet
    :type token_symbol: bool

    :return: the propagated transaction so others can spend their outputs
    """
    wallet = manager.wallet

    if address_b58 is None:
        address_b58 = wallet.get_unused_address(mark_as_used=True)
    address = decode_address(address_b58)
    script = P2PKH.create_output_script(address)

    deposit_amount = get_deposit_amount(mint_amount)
    genesis = manager.tx_storage.get_all_genesis()
    genesis_blocks = [tx for tx in genesis if tx.is_block]
    genesis_txs = [tx for tx in genesis if not tx.is_block]
    genesis_block = genesis_blocks[0]
    genesis_private_key = get_genesis_key()

    if use_genesis:
        deposit_input = [TxInput(genesis_block.hash, 0, b'')]
        change_output = TxOutput(genesis_block.outputs[0].value - deposit_amount, script, 0)
        parents = [tx.hash for tx in genesis_txs]
        timestamp = int(manager.reactor.seconds())
    else:
        total_reward = 0
        deposit_input = []
        while total_reward < deposit_amount:
            block = add_new_block(manager, advance_clock=1, address=address)
            deposit_input.append(TxInput(block.hash, 0, b''))
            total_reward += block.outputs[0].value

        if total_reward > deposit_amount:
            change_output = TxOutput(total_reward - deposit_amount, script, 0)
        else:
            change_output = None

        add_blocks_unlock_reward(manager)
        timestamp = int(manager.reactor.seconds())
        parents = manager.get_new_tx_parents(timestamp)

    outputs = []
    # mint output
    if mint_amount > 0:
        outputs.append(TxOutput(mint_amount, script, 0b00000001))
    # authority outputs
    outputs.append(TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001))
    outputs.append(TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001))
    # deposit output
    if change_output:
        outputs.append(change_output)

    tx = TokenCreationTransaction(
        weight=1,
        parents=parents,
        storage=manager.tx_storage,
        inputs=deposit_input,
        outputs=outputs,
        token_name=token_name,
        token_symbol=token_symbol,
        timestamp=timestamp
    )
    data_to_sign = tx.get_sighash_all()
    if use_genesis:
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, genesis_private_key)
    else:
        private_key = wallet.get_private_key(address_b58)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, private_key)

    for input_ in tx.inputs:
        input_.data = P2PKH.create_input_data(public_bytes, signature)

    tx.resolve()
    if propagate:
        tx.verify()
        manager.propagate_tx(tx, fails_silently=False)
        manager.reactor.advance(8)
    return tx


def start_remote_storage(tx_storage=None):
    """ Starts a remote storage

        :param tx_storage: storage to run in the remote storage
        :type tx_storage: :py:class:`hathor.transaction.storage.TransactionStorage`

        :return: Remote tx storage and the remote server
        :rtype: Tuple[:py:class:`hathor.transaction.storage.TransactionRemoteStorage`, grpc server]
    """
    if not tx_storage:
        tx_storage = TransactionMemoryStorage()

    _server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    tx_storage._manually_initialize()
    _servicer, port = create_transaction_storage_server(_server, tx_storage)
    _server.start()

    tx_storage = TransactionRemoteStorage()
    tx_storage.connect_to(port)

    return tx_storage, _server
