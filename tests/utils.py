from twisted.test import proto_helpers
import random
import subprocess
import requests
import time
import urllib.parse


def resolve_block_bytes(block_bytes):
    """ From block bytes we create a block and resolve pow
        Return block bytes with hash and nonce after pow
        :rtype: bytes
    """
    from hathor.transaction import Block
    import base64
    block_bytes = base64.b64decode(block_bytes)
    block = Block.create_from_struct(block_bytes)
    block.weight = 10
    block.resolve()
    return block.get_struct()


def gen_new_tx(manager, address, value, verify=True):
    from hathor.transaction import Transaction
    from hathor.wallet.base_wallet import WalletOutputInfo

    outputs = []
    outputs.append(WalletOutputInfo(address=manager.wallet.decode_address(address), value=int(value), timelock=None))

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


def add_new_block(manager, advance_clock=None):
    """ Create, resolve and propagate a new block

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :return: Block created
        :rtype: :py:class:`hathor.transaction.block.Block`
    """
    block = manager.generate_mining_block()
    block.resolve()
    block.verify()
    manager.propagate_tx(block)
    if advance_clock:
        manager.reactor.advance(advance_clock)
    return block


def add_new_blocks(manager, num_blocks, advance_clock=None):
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
        blocks.append(add_new_block(manager, advance_clock))
    return blocks


class FakeConnection:
    def __init__(self, server_manager, client_manager):
        self.server_manager = server_manager
        self.client_manager = client_manager

        self.proto1 = server_manager.server_factory.buildProtocol(('127.0.0.1', 0))
        self.proto2 = client_manager.client_factory.buildProtocol(('127.0.0.1', 0))

        self.tr1 = proto_helpers.StringTransport()
        self.tr2 = proto_helpers.StringTransport()

        self.proto1.makeConnection(self.tr1)
        self.proto2.makeConnection(self.tr2)

    def run_one_step(self, debug=False):
        line1 = self.tr1.value()
        line2 = self.tr2.value()

        if debug:
            print('--')
            print('line1', line1)
            print('line2', line2)
            print('--')

        self.tr1.clear()
        self.tr2.clear()

        if line1:
            self.proto2.dataReceived(line1)
        if line2:
            self.proto1.dataReceived(line2)

    def disconnect(self, reason):
        self.tr1.loseConnection()
        self.proto1.connectionLost(reason)
        self.tr2.loseConnection()
        self.proto2.connectionLost(reason)

    def is_empty(self):
        return not self.tr1.value() and not self.tr2.value()


def run_server(hostname='localhost', listen=8005, status=8085, tries=50):
    command = 'bash hathor-cli run_node --hostname {} --listen tcp:{} --status {}'.format(hostname, listen, status)
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
