import base64
import json
import os
import random
import subprocess
import time
import urllib.parse
from concurrent import futures
from typing import List

import grpc
import numpy.random
import requests
from twisted.internet.task import Clock
from twisted.test import proto_helpers

from hathor.constants import DECIMAL_PLACES, HATHOR_TOKEN_UID, TOKENS_PER_BLOCK
from hathor.crypto.util import decode_address, get_private_key_from_bytes
from hathor.manager import HathorEvents, HathorManager
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.storage import (
    TransactionMemoryStorage,
    TransactionRemoteStorage,
    create_transaction_storage_server,
)


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
    manager.propagate_tx(tx)
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
        address = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        value = random.choice([5, 10, 15, 20])
        tx = add_new_tx(manager, address, value, advance_clock)
        txs.append(tx)
    return txs


def add_new_block(manager, advance_clock=None, *, parent_block_hash=None, data=b''):
    """ Create, resolve and propagate a new block

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :return: Block created
        :rtype: :py:class:`hathor.transaction.block.Block`
    """
    block = manager.generate_mining_block(parent_block_hash=parent_block_hash, data=data)
    block.resolve()
    block.verify()
    manager.propagate_tx(block)
    if advance_clock:
        manager.reactor.advance(advance_clock)
    return block


def add_new_blocks(manager, num_blocks, advance_clock=None, *, parent_block_hash=None, block_data=b''):
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
        blocks.append(add_new_block(manager, advance_clock, parent_block_hash=parent_block_hash, data=block_data))
        if parent_block_hash:
            parent_block_hash = blocks[-1].hash
    return blocks


class FakeConnection:
    def __init__(self, manager1, manager2, *, latency: float = 0):
        """
        :param: latency: Latency between nodes in seconds
        """
        self.manager1 = manager1
        self.manager2 = manager2

        self.latency = latency
        self.is_connected = True

        self.proto1 = manager1.server_factory.buildProtocol(('127.0.0.1', 0))
        self.proto2 = manager2.client_factory.buildProtocol(('127.0.0.1', 0))

        self.tr1 = proto_helpers.StringTransport()
        self.tr2 = proto_helpers.StringTransport()

        self.proto1.makeConnection(self.tr1)
        self.proto2.makeConnection(self.tr2)

    def run_one_step(self, debug=False, force=False):
        if not self.is_connected:
            raise Exception()

        line1 = self.tr1.value()
        line2 = self.tr2.value()

        self.tr1.clear()
        self.tr2.clear()

        if self.latency > 0:
            if line1:
                self.manager1.reactor.callLater(self.latency, self.deliver_message, self.proto2, line1)
            if line2:
                self.manager2.reactor.callLater(self.latency, self.deliver_message, self.proto1, line2)

        else:
            if line1:
                self.proto2.dataReceived(line1)
                if debug:
                    print('[1->2]', line1)

            if line2:
                self.proto1.dataReceived(line2)
                if debug:
                    print('[2->1]', line2)

        return True

    def deliver_message(self, proto, data):
        proto.dataReceived(data)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self.proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self.proto2.connectionLost(reason)
        self.is_connected = False

    def is_empty(self):
        return not self.tr1.value() and not self.tr2.value()


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
    def __init__(self, manager: HathorManager, *, hashpower: float, version: int = 1):
        """
        :param: hashpower: Number of hashes per second
        """
        self.manager = manager
        self.hashpower = hashpower
        self.version = version
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
            assert self.manager.propagate_tx(self.block)
            self.block = None

        block = self.manager.generate_mining_block(version=self.version)
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
            self.manager.propagate_tx(self.tx)
            self.tx = None

        dt = random.expovariate(self.rate)
        self.delayedcall = self.clock.callLater(dt, self.new_tx_step1)

    def new_tx_step1(self):
        """ Generate a new transaction and schedule the mining part of the transaction.
        """
        balance = self.manager.wallet.balance[HATHOR_TOKEN_UID]
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


def run_server(hostname='localhost', listen=8005, listen_ssl=False, status=8085, bootstrap=None, tries=100):
    """ Starts a full node in a subprocess running the cli command

        :param hostname: Hostname used to be accessed by other peers
        :type hostname: str

        :param listen: Port to listen for new connections (eg: 8000)
        :type listen: int

        :param listen_ssl: Listen to ssl connection
        :type listen_ssl: bool

        :param status: Port to run status server
        :type status: int

        :param bootstrap: Address to connect to (eg: tcp:127.0.0.1:8000)
        :type bootstrap: str

        :param tries: How many loop tries we will have waiting for the node to run
        :type tries: int

        :return: Subprocess created
        :rtype: :py:class:`subprocess.Popen`
    """
    command = 'python -m hathor run_node --hostname {} --listen tcp:{} --status {}'.format(hostname, listen, status)
    if listen_ssl:
        command = '{} --ssl'.format(command)

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


def request_server(path, method, host='http://localhost', port=8085, data=None):
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
    partial_url = '{}:{}'.format(host, port)
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


def get_tokens_from_mining(blocks_mined):
    """ Return the tokens available expected after mining

        :param blocks_mined: number of blocks that were mined
        :type blocks_mined: int

        :return: Available tokens after blocks were mined
        :rtype: int
    """
    tokens_issued_per_block = TOKENS_PER_BLOCK * (10**DECIMAL_PLACES)
    return tokens_issued_per_block * blocks_mined


def get_genesis_key():
    # read genesis keys
    filepath = os.path.join(os.getcwd(), 'hathor/wallet/genesis_keys.json')
    dict_data = None
    with open(filepath, 'r') as json_file:
        dict_data = json.loads(json_file.read())
    b64_private_key = dict_data['private_key']
    private_key_bytes = base64.b64decode(b64_private_key)
    return get_private_key_from_bytes(private_key_bytes)


def create_tokens(manager: 'HathorManager', address_b58: str = None, genesis_index: int = 0):
    """Creates a new token and propagates a tx with the following UTXOs:
    1. some tokens (already mint some tokens so they can be transferred);
    2. mint authority;
    3. melt authority;

    :param manager: hathor manager
    :type manager: :class:`hathor.manager.HathorManager`

    :param address_b58: address where tokens will be transferred to
    :type address_b58: string

    :param genesis_index: which genesis output to use for creating the token
    :type genesis_index: int

    :return: the propagated transaction so others can spend their outputs
    """
    genesis = manager.tx_storage.get_all_genesis()
    genesis_blocks = [tx for tx in genesis if tx.is_block]
    genesis_txs = [tx for tx in genesis if not tx.is_block]
    genesis_block = genesis_blocks[genesis_index]
    genesis_private_key = get_genesis_key()

    wallet = manager.wallet

    if address_b58 is None:
        address_b58 = wallet.get_unused_address(mark_as_used=True)
    address = decode_address(address_b58)

    _input1 = TxInput(genesis_block.hash, genesis_index, b'')

    # we send genesis tokens to a random address so we don't add hathors to the user's wallet
    rand_address = decode_address('1Pa4MMsr5DMRAeU1PzthFXyEJeVNXsMHoz')
    rand_script = P2PKH.create_output_script(rand_address)
    value = genesis_block.outputs[genesis_index].value
    output = TxOutput(value, rand_script, 0)

    parents = [tx.hash for tx in genesis_txs]
    tx = Transaction(
        weight=1,
        inputs=[_input1],
        parents=parents,
        storage=manager.tx_storage,
        timestamp=int(manager.reactor.seconds())
    )

    # create token
    token_masks = TxOutput.TOKEN_CREATION_MASK | TxOutput.TOKEN_MINT_MASK | TxOutput.TOKEN_MELT_MASK
    new_token_uid = tx.create_token_uid(0)
    tx.tokens.append(new_token_uid)
    script = P2PKH.create_output_script(address)
    token_output = TxOutput(token_masks, script, 0b10000001)

    # finish and propagate tx
    tx.outputs = [token_output, output]
    data_to_sign = tx.get_sighash_all(clear_input_data=True)
    public_bytes, signature = wallet.get_input_aux_data(data_to_sign, genesis_private_key)
    tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
    tx.resolve()
    tx.verify()
    manager.propagate_tx(tx)
    manager.reactor.advance(8)

    # mint tokens
    parents = manager.get_new_tx_parents()
    _input1 = TxInput(tx.hash, 0, b'')
    # mint 300 tokens
    token_output1 = TxOutput(300, script, 0b00000001)
    token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
    token_output3 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
    tx2 = Transaction(
        weight=1,
        inputs=[_input1],
        outputs=[token_output1, token_output2, token_output3],
        parents=parents,
        tokens=[new_token_uid],
        storage=manager.tx_storage,
        timestamp=int(manager.reactor.seconds())
    )
    data_to_sign = tx2.get_sighash_all(clear_input_data=True)
    public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(address_b58))
    tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
    tx2.resolve()
    tx2.verify()
    manager.propagate_tx(tx2)
    manager.reactor.advance(8)
    return tx2


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
