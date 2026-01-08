import base64
import os
import string
import subprocess
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional, cast

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.internet.task import Clock

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_public_key
from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_data import TxData, TxMetadata
from hathor.event.model.event_type import EventType
from hathor.manager import HathorManager
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.simulator.utils import add_new_block, add_new_blocks, gen_new_double_spending, gen_new_tx
from hathor.transaction import BaseTransaction, Block, Transaction, TxInput, TxOutput
from hathor.transaction.headers import FeeHeader
from hathor.transaction.headers.fee_header import FeeHeaderEntry
from hathor.transaction.scripts import P2PKH, HathorScript, Opcode, parse_address_script
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount
from hathor.util import Random
from hathorlib.scripts import DataScript

settings = HathorSettings()

# useful for adding blocks to a different wallet
BURN_ADDRESS = bytes.fromhex('28acbfb94571417423c1ed66f706730c4aea516ac5762cccb8')

DEFAULT_WORDS: str = (
    'bind daring above film health blush during tiny neck slight clown salmon '
    'wine brown good setup later omit jaguar tourist rescue flip pet salute'
)


def resolve_block_bytes(*, block_bytes: bytes, cpu_mining_service: CpuMiningService) -> bytes:
    """ From block bytes we create a block and resolve pow
        Return block bytes with hash and nonce after pow
        :rtype: bytes
    """
    from hathor.transaction import Block
    block_bytes = base64.b64decode(block_bytes)
    block = Block.create_from_struct(block_bytes)
    cpu_mining_service.resolve(block)
    return block.get_struct()


def add_custom_tx(
    manager: HathorManager,
    tx_inputs: list[tuple[BaseTransaction, int]],
    *,
    n_outputs: int = 1,
    base_parent: Optional[Transaction] = None,
    weight: Optional[float] = None,
    resolve: bool = False,
    address: Optional[str] = None,
    inc_timestamp: int = 0
) -> Transaction:
    """Add a custom tx based on the gen_custom_tx(...) method."""
    tx = gen_custom_tx(manager,
                       tx_inputs,
                       n_outputs=n_outputs,
                       base_parent=base_parent,
                       weight=weight,
                       resolve=resolve,
                       address=address,
                       inc_timestamp=inc_timestamp)
    manager.propagate_tx(tx)
    return tx


def gen_custom_tx(manager: HathorManager,
                  tx_inputs: list[tuple[BaseTransaction, int]],
                  *,
                  n_outputs: int = 1,
                  base_parent: Optional[Transaction] = None,
                  weight: Optional[float] = None,
                  resolve: bool = False,
                  address: Optional[str] = None,
                  inc_timestamp: int = 0) -> Transaction:
    """Generate a custom tx based on the inputs and outputs. It gives full control to the
    inputs and can be used to generate conflicts and specific patterns in the DAG."""
    tx = gen_custom_base_tx(manager,
                            tx_inputs,
                            n_outputs=n_outputs,
                            base_parent=base_parent,
                            weight=weight,
                            resolve=resolve,
                            address=address,
                            inc_timestamp=inc_timestamp)
    return cast(Transaction, tx)


def gen_custom_base_tx(manager: HathorManager,
                       tx_inputs: list[tuple[BaseTransaction, int]],
                       *,
                       n_outputs: int = 1,
                       base_parent: Optional[Transaction] = None,
                       weight: Optional[float] = None,
                       resolve: bool = False,
                       address: Optional[str] = None,
                       inc_timestamp: int = 0,
                       cls: type[BaseTransaction] = Transaction) -> BaseTransaction:
    """Generate a custom tx based on the inputs and outputs. It gives full control to the
    inputs and can be used to generate conflicts and specific patterns in the DAG."""
    wallet = manager.wallet
    assert wallet is not None

    inputs = []
    value = 0
    parents = []
    for tx_base, txout_index in tx_inputs:
        spent_tx = tx_base
        spent_txout = spent_tx.outputs[txout_index]
        p2pkh = parse_address_script(spent_txout.script)
        assert isinstance(p2pkh, P2PKH)

        from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
        value += spent_txout.value
        private_key = wallet.get_private_key(p2pkh.address)
        inputs.append(WalletInputInfo(tx_id=spent_tx.hash, index=txout_index, private_key=private_key))
        if not tx_base.is_block:
            parents.append(tx_base.hash)

    output_address: str
    if address is None:
        output_address = wallet.get_unused_address(mark_as_used=True)
    else:
        output_address = address
    if n_outputs == 1:
        outputs = [WalletOutputInfo(address=decode_address(output_address), value=int(value), timelock=None)]
    elif n_outputs == 2:
        assert int(value) > 1
        outputs = [
            WalletOutputInfo(address=decode_address(output_address), value=int(value) - 1, timelock=None),
            WalletOutputInfo(address=decode_address(output_address), value=1, timelock=None),
        ]
    else:
        raise NotImplementedError

    tx2 = wallet.prepare_transaction(cls, inputs, outputs)
    tx2.storage = manager.tx_storage
    tx2.timestamp = max(tx_base.timestamp + 1, int(manager.reactor.seconds()))

    tx2.parents = parents[:2]
    if len(tx2.parents) < 2:
        if base_parent:
            tx2.parents.append(base_parent.hash)
        elif not tx_base.is_block:
            tx2.parents.append(tx_base.parents[0])
        else:
            tx2.parents.extend(manager.get_new_tx_parents(tx2.timestamp))
            tx2.parents = tx2.parents[:2]
    assert len(tx2.parents) == 2

    tx2.weight = weight or 25
    tx2.timestamp += inc_timestamp
    if resolve:
        manager.cpu_mining_service.resolve(tx2)
    else:
        tx2.update_hash()
    return tx2


def add_new_double_spending(manager: HathorManager, *, use_same_parents: bool = False,
                            tx: Optional[Transaction] = None, weight: float = 1) -> Transaction:
    tx = gen_new_double_spending(manager, use_same_parents=use_same_parents, tx=tx, weight=weight)
    manager.propagate_tx(tx)
    return tx


def add_new_tx(
    manager: HathorManager,
    address: str,
    value: int,
    advance_clock: int = 1,
    propagate: bool = True,
    name: str | None = None,
) -> Transaction:
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
    tx.name = name
    if propagate:
        manager.propagate_tx(tx)
    if advance_clock:
        manager.reactor.advance(advance_clock)  # type: ignore[attr-defined]
    return tx


def add_new_transactions(
    manager: HathorManager,
    num_txs: int,
    advance_clock: int = 1,
    propagate: bool = True,
    name: str | None = None,
) -> list[Transaction]:
    """ Create, resolve and propagate some transactions

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :param num_txs: Quantity of txs to be created
        :type num_txs: int

        :return: Transactions created
        :rtype: list[Transaction]
    """
    txs = []
    for i in range(num_txs):
        address = 'HGov979VaeyMQ92ubYcnVooP6qPzUJU8Ro'
        value = manager.rng.choice([5, 10, 15, 20])
        tx_name = f'{name}-{i}' if num_txs > 1 else name
        tx = add_new_tx(manager, address, value, advance_clock, propagate, name=tx_name)
        txs.append(tx)
    return txs


def add_blocks_unlock_reward(manager: HathorManager) -> list[Block]:
    """This method adds new blocks to a 'burn address' to make sure the existing
    block rewards can be spent. It uses a 'burn address' so the manager's wallet
    is not impacted.
    """
    return add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1, address=BURN_ADDRESS)


def run_server(
    hostname: str = 'localhost',
    listen: int = 8005,
    status: int = 8085,
    bootstrap: str | None = None,
    tries: int = 100,
    alive_for_at_least_sec: int = 3
) -> subprocess.Popen[bytes]:
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
        '--temp-data',
        '--wallet hd',
        '--wallet-enable-api',
        '--hostname {}'.format(hostname),
        '--listen tcp:{}'.format(listen),
        '--status {}'.format(status),
        # We must allow mining without peers, otherwise some tests won't be able to mine.
        '--allow-mining-without-peers',
        '--wallet-index',
        # Disable whitelist for testing (empty whitelist with restrictive policy blocks all)
        '--x-p2p-whitelist disabled'
    ])

    if bootstrap:
        command = '{} --bootstrap {}'.format(command, bootstrap)

    process = subprocess.Popen(command.split(), env=os.environ)

    # check that the process doesn't close in the first few seconds
    for _ in range(alive_for_at_least_sec):
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(f'remote process died with {exit_code}')

    partial_url = 'http://{}:{}'.format(hostname, status)
    url = urllib.parse.urljoin(partial_url, '/wallet/balance/')
    while True:
        try:
            exit_code = process.poll()
            if exit_code is not None:
                raise RuntimeError(f'remote process died with {exit_code}')
            requests.get(url)
            break
        except requests.exceptions.ConnectionError:
            tries -= 1
            if tries == 0:
                raise TimeoutError('Error when running node for testing')
            time.sleep(0.1)

    return process


def request_server(
    path: str,
    method: str,
    host: str = 'http://localhost',
    port: int = 8085,
    data: dict[str, Any] | None = None,
    prefix: str = settings.API_VERSION_PREFIX
) -> dict[str, Any]:
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
        :type data: dict

        :return: Response in json format
        :rtype: dict (json)
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
    json_response: dict[str, Any] = response.json()
    return json_response


def execute_mining(
    path: str = 'mining',
    *,
    count: int,
    host: str = 'http://localhost',
    port: int = 8085,
    prefix: str = settings.API_VERSION_PREFIX
) -> None:
    """Execute a mining on a given server"""
    from hathor_cli.mining import create_parser, execute
    partial_url = '{}:{}/{}/'.format(host, port, prefix)
    url = urllib.parse.urljoin(partial_url, path)
    parser = create_parser()
    args = parser.parse_args([url, '--count', str(count)])
    execute(args)


def execute_tx_gen(
    *,
    count: int,
    address: str | None = None,
    value: int | None = None,
    timestamp: str | None = None,
    host: str = 'http://localhost',
    port: int = 8085,
    prefix: str = settings.API_VERSION_PREFIX
) -> None:
    """Execute a tx generator on a given server"""
    from hathor_cli.tx_generator import create_parser, execute
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


def get_genesis_key() -> ec.EllipticCurvePrivateKey:
    from hathor.wallet import HDWallet
    wallet = HDWallet(words=GENESIS_SEED)
    wallet._manually_initialize()
    key = wallet.get_key_at_index(0)
    return ec.derive_private_key(
        int.from_bytes(key.secret_exponent().to_bytes(32, 'big'), 'big'),
        ec.SECP256K1(),
        backend=default_backend()
    )


GENESIS_SEED = ('coral light army gather adapt blossom school alcohol coral light army gather '
                'adapt blossom school alcohol coral light army gather adapt blossom school awesome')
GENESIS_PRIVATE_KEY = get_genesis_key()
GENESIS_PUBLIC_KEY = GENESIS_PRIVATE_KEY.public_key()
GENESIS_ADDRESS_B58 = get_address_b58_from_public_key(GENESIS_PUBLIC_KEY)


def create_tokens(manager: 'HathorManager', address_b58: Optional[str] = None, mint_amount: int = 300,
                  token_name: str = 'TestCoin', token_symbol: str = 'TTC', propagate: bool = True,
                  use_genesis: bool = True, nft_data: Optional[str] = None) -> TokenCreationTransaction:
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

    :param nft_data: If not None we create a first output as the NFT data script
    :type nft_data: str

    :return: the propagated transaction so others can spend their outputs
    """
    wallet = manager.wallet
    assert wallet is not None

    if address_b58 is None:
        address_b58 = wallet.get_unused_address(mark_as_used=True)
    address = decode_address(address_b58)
    script = P2PKH.create_output_script(address)

    deposit_amount = get_deposit_token_deposit_amount(manager._settings, mint_amount)
    if nft_data:
        # NFT creation needs 0.01 HTR of fee
        deposit_amount += 1
    genesis = manager.tx_storage.get_all_genesis()
    genesis_blocks = [tx for tx in genesis if tx.is_block]
    genesis_txs = [tx for tx in genesis if not tx.is_block]
    genesis_block = genesis_blocks[0]
    genesis_private_key = get_genesis_key()

    change_output: Optional[TxOutput]
    parents: list[bytes]
    timestamp: int | None = None
    if use_genesis:
        genesis_hash = genesis_block.hash
        assert genesis_hash is not None
        deposit_input = [TxInput(genesis_hash, 0, b'')]
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

        unlock_blocks = add_blocks_unlock_reward(manager)
        timestamp = unlock_blocks[-1].timestamp + 1
        assert timestamp is not None
        parents = manager.get_new_tx_parents(timestamp)

    outputs = []
    if nft_data:
        script_data = DataScript.create_output_script(nft_data)
        output_data = TxOutput(1, script_data, 0)
        outputs.append(output_data)
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

    manager.cpu_mining_service.resolve(tx)
    if propagate:
        manager.propagate_tx(tx)
        assert isinstance(manager.reactor, Clock)
        manager.reactor.advance(8)
    return tx


def create_fee_tokens(
    manager: 'HathorManager',
    address_b58: Optional[str] = None,
    mint_amount: int = 300,
    token_name: str = 'TestFeeCoin',
    token_symbol: str = 'TFC',
    genesis_output_amount: Optional[int] = None,
    propagate: bool = True,
) -> TokenCreationTransaction:
    """Creates a new token and propagates a tx with the following UTXOs:
    0. some tokens (already mint some tokens so they can be transferred);
    1. mint authority;
    2. melt authority;
    3. fee change | genesis_output_amount;
    4. genesis change; (only when genesis_output_amount is not None)

    :param manager: hathor manager
    :type manager: :class:`hathor.manager.HathorManager`

    :param address_b58: address where tokens will be transferred to
    :type address_b58: string

    :param token_name: the token name for the new token
    :type token_name: str

    :param token_symbol: the token symbol for the new token
    :type token_symbol: str

    :return: the propagated transaction so others can spend their outputs
    """
    wallet = manager.wallet
    assert wallet is not None

    if address_b58 is None:
        address_b58 = wallet.get_unused_address(mark_as_used=True)
    address = decode_address(address_b58)
    script = P2PKH.create_output_script(address)

    genesis = manager.tx_storage.get_all_genesis()
    genesis_blocks = [tx for tx in genesis if tx.is_block]
    genesis_txs = [tx for tx in genesis if not tx.is_block]
    genesis_block = genesis_blocks[0]
    genesis_private_key = get_genesis_key()

    parents = [tx.hash for tx in genesis_txs]

    genesis_hash = genesis_block.hash
    assert genesis_hash is not None

    deposit_input = [TxInput(genesis_hash, 0, b'')]
    timestamp = int(manager.reactor.seconds())

    outputs = []
    # mint output
    outputs.append(TxOutput(mint_amount, script, 0b00000001))

    # authority outputs
    outputs.append(TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001))
    outputs.append(TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001))

    # fee
    fee = settings.FEE_PER_OUTPUT

    # fee output
    outputs.append(TxOutput(genesis_block.outputs[0].value - fee - (genesis_output_amount or 0), script, 0))
    if genesis_output_amount:
        outputs.append(TxOutput(genesis_output_amount, script, 0))

    tx = TokenCreationTransaction(
        weight=1,
        parents=parents,
        storage=manager.tx_storage,
        inputs=deposit_input,
        outputs=outputs,
        token_name=token_name,
        token_symbol=token_symbol,
        timestamp=timestamp,
        token_version=TokenVersion.FEE
    )

    tx.headers.append(FeeHeader(
        settings=manager._settings,
        tx=tx,
        fees=[FeeHeaderEntry(token_index=0, amount=fee)])
    )
    data_to_sign = tx.get_sighash_all()

    public_bytes, signature = wallet.get_input_aux_data(data_to_sign, genesis_private_key)

    for input_ in tx.inputs:
        input_.data = P2PKH.create_input_data(public_bytes, signature)

    manager.cpu_mining_service.resolve(tx)

    if propagate:
        manager.propagate_tx(tx)
        assert isinstance(manager.reactor, Clock)
        manager.reactor.advance(8)

    return tx


def get_deposit_token_amount_from_htr(htr_amount: int) -> int:
    """
    Calculate how many tokens correspond to a given HTR amount based on the
    configured TOKEN_DEPOSIT_PERCENTAGE.

    Returns
    -------
    int
        The smallest integer number of tokens that covers the given HTR amount.
    Raises
    ------
    AssertionError
        If the computed token amount is not an integer (this should not occur
        when TOKEN_DEPOSIT_PERCENTAGE is a positive divisor).
    """
    token_amount = abs(htr_amount / settings.TOKEN_DEPOSIT_PERCENTAGE)
    assert token_amount.is_integer()
    return int(token_amount)


def create_script_with_sigops(nops: int) -> bytes:
    """ Generate a script with multiple OP_CHECKMULTISIG that amounts to `nops` sigops
    """
    hscript = HathorScript()
    # each step adds 16 sigops up to `nops`, but not exceding nops
    for _ in range(nops // 16):
        hscript.addOpcode(Opcode.OP_16)
        hscript.addOpcode(Opcode.OP_CHECKMULTISIG)

    # add `nops % 16` sigops
    hscript.addOpcode(getattr(Opcode, 'OP_{}'.format(nops % 16)))
    hscript.addOpcode(Opcode.OP_CHECKMULTISIG)
    return hscript.data


def add_tx_with_data_script(manager: 'HathorManager', data: list[str], propagate: bool = True) -> Transaction:
    """ This method will create and propagate a transaction with only data script outputs
    """
    wallet = manager.wallet
    assert wallet is not None

    # Get address to send the change and mined blocks reward
    address_b58 = wallet.get_unused_address(mark_as_used=True)
    address = decode_address(address_b58)
    script = P2PKH.create_output_script(address)

    # Each data script output requires 0.01 HTR to burn
    burn_amount = len(data)

    # Get the inputs to be used to burn the HTR
    total_reward = 0
    burn_input = []
    while total_reward < burn_amount:
        block = add_new_block(manager, advance_clock=1, address=address)
        burn_input.append(TxInput(block.hash, 0, b''))
        total_reward += block.outputs[0].value

    # Create the change output, if needed
    change_output: Optional[TxOutput]
    if total_reward > burn_amount:
        change_output = TxOutput(total_reward - burn_amount, script, 0)
    else:
        change_output = None

    # Unlock the rewards to be used
    add_blocks_unlock_reward(manager)

    # Calculate tx timestamp and parents
    timestamp = int(manager.reactor.seconds())
    parents = manager.get_new_tx_parents(timestamp)

    # Create the outputs with data script
    outputs = []
    for d in data:
        script_data = DataScript.create_output_script(d)
        output_data = TxOutput(1, script_data, 0)
        outputs.append(output_data)

    # Add change output to array
    if change_output:
        outputs.append(change_output)

    tx = Transaction(
        weight=1,
        parents=parents,
        storage=manager.tx_storage,
        inputs=burn_input,
        outputs=outputs,
        timestamp=timestamp
    )

    # Sign the inputs
    data_to_sign = tx.get_sighash_all()
    private_key = wallet.get_private_key(address_b58)
    public_bytes, signature = wallet.get_input_aux_data(data_to_sign, private_key)

    for input_ in tx.inputs:
        input_.data = P2PKH.create_input_data(public_bytes, signature)

    manager.cpu_mining_service.resolve(tx)

    if propagate:
        manager.propagate_tx(tx)
        assert isinstance(manager.reactor, Clock)
        manager.reactor.advance(8)

    return tx


@dataclass
class EventMocker:
    rng: Random
    next_id: int = 0
    tx_data = TxData(
        hash='abc',
        name='tx name',
        nonce=123,
        timestamp=456,
        signal_bits=0,
        version=1,
        weight=10,
        inputs=[],
        outputs=[],
        parents=[],
        tokens=[],
        metadata=TxMetadata(
            hash='abc',
            spent_outputs=[],
            conflict_with=[],
            voided_by=[],
            received_by=[],
            twins=[],
            accumulated_weight=10.0,
            score=20.0,
            accumulated_weight_raw="1024",
            score_raw="1048576",
            height=100,
            validation='validation'
        )
    )

    def gen_next_id(self) -> int:
        next_id = self.next_id
        self.next_id += 1
        return next_id

    def generate_mocked_event(self, event_id: Optional[int] = None, group_id: Optional[int] = None) -> BaseEvent:
        """ Generates a mocked event with the best block found message
        """
        return BaseEvent(
            id=event_id or self.gen_next_id(),
            timestamp=1658892990,
            type=EventType.VERTEX_METADATA_CHANGED,
            group_id=group_id,
            data=self.tx_data,
        )

    def generate_random_word(self, length: int) -> str:
        """ Generates a random sequence of characters given a length
        """
        letters = string.ascii_lowercase
        return ''.join(self.rng.choice(letters) for i in range(length))

    @classmethod
    def create_event(cls, event_id: int) -> BaseEvent:
        """ Generates a mocked event with fixed properties, except the ID
        """
        return BaseEvent(
            id=event_id,
            timestamp=123456,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=cls.tx_data
        )
