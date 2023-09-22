#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import base64
from typing import Optional, cast
from twisted.internet.task import Clock

from hathorlib.scripts import DataScript

from hathor.conf import HathorSettings
from hathor.manager import HathorManager
from hathor.crypto.util import decode_address, get_private_key_from_bytes
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.scripts import P2PKH
from hathor.transaction.util import get_deposit_amount


settings = HathorSettings()
BURN_ADDRESS = bytes.fromhex('28acbfb94571417423c1ed66f706730c4aea516ac5762cccb8')


def add_blocks_unlock_reward(manager):
    """This method adds new blocks to a 'burn address' to make sure the existing
    block rewards can be spent. It uses a 'burn address' so the manager's wallet
    is not impacted.
    """
    return add_new_blocks(manager,
                          settings.REWARD_SPEND_MIN_BLOCKS,
                          advance_clock=1,
                          address=BURN_ADDRESS)


def get_genesis_key():
    private_key_bytes = base64.b64decode(
        'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgOCgCddzDZsfKgiMJLOt97eov9RLwHeePyBIK2WPF8MChRA'
        'NCAAQ/XSOK+qniIY0F3X+lDrb55VQx5jWeBLhhzZnH6IzGVTtlAj9Ki73DVBm5+VXK400Idd6ddzS7FahBYYC7IaTl'
    )
    return get_private_key_from_bytes(private_key_bytes)


def create_tokens(manager: 'HathorManager', address_b58: Optional[str] = None,
                  mint_amount: int = 300, token_name: str = 'TestCoin',
                  token_symbol: str = 'TTC', propagate: bool = True,
                  use_genesis: bool = True,
                  nft_data: Optional[str] = None) -> TokenCreationTransaction:
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

    deposit_amount = get_deposit_amount(mint_amount)
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

    if use_genesis:
        genesis_hash = genesis_block.hash
        assert genesis_hash is not None
        deposit_input = [TxInput(genesis_hash, 0, b'')]
        change_output = TxOutput((genesis_block.outputs[0].value -
                                  deposit_amount),
                                 script, 0)
        parents = [cast(bytes, tx.hash) for tx in genesis_txs]
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
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign,
                                                            genesis_private_key)
    else:
        private_key = wallet.get_private_key(address_b58)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign,
                                                            private_key)

    for input_ in tx.inputs:
        input_.data = P2PKH.create_input_data(public_bytes, signature)

    tx.resolve()
    if propagate:
        tx.verify()
        manager.propagate_tx(tx, fails_silently=False)
        assert isinstance(manager.reactor, Clock)
        manager.reactor.advance(8)
    return tx


def gen_new_tx(manager, address, value, verify=True):
    from hathor.transaction import Transaction
    from hathor.wallet.base_wallet import WalletOutputInfo

    outputs = []
    outputs.append(WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

    tx = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
    tx.storage = manager.tx_storage

    max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
    tx.timestamp = max(max_ts_spent_tx + 1, int(manager.reactor.seconds()))

    tx.weight = 1
    tx.parents = manager.get_new_tx_parents(tx.timestamp)
    tx.resolve()
    if verify:
        tx.verify()
    return tx


def add_new_blocks(manager, num_blocks, advance_clock=None, *, parent_block_hash=None,
                   block_data=b'', weight=None, address=None):
    """ Create, resolve and propagate some blocks

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :param num_blocks: Quantity of blocks to be created
        :type num_blocks: int

        :return: Blocks created
        :rtype: list[Block]
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


def add_new_block(manager, advance_clock=None, *, parent_block_hash=None,
                  data=b'', weight=None, address=None, propagate=True):
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
    block.validate_full()
    if propagate:
        manager.propagate_tx(block, fails_silently=False)
    if advance_clock:
        manager.reactor.advance(advance_clock)
    return block


class NoCandidatesError(Exception):
    pass


def gen_new_double_spending(manager: HathorManager, *, use_same_parents: bool = False,
                            tx: Optional[Transaction] = None, weight: float = 1) -> Transaction:
    if tx is None:
        tx_candidates = manager.get_new_tx_parents()
        genesis = manager.tx_storage.get_all_genesis()
        genesis_txs = [tx for tx in genesis if not tx.is_block]
        # XXX: it isn't possible to double-spend a genesis transaction, thus we remove it from tx_candidates
        for genesis_tx in genesis_txs:
            if genesis_tx.hash in tx_candidates:
                tx_candidates.remove(genesis_tx.hash)
        if not tx_candidates:
            raise NoCandidatesError()
        # assert tx_candidates, 'Must not be empty, otherwise test was wrongly set up'
        tx_hash = manager.rng.choice(tx_candidates)
        tx = cast(Transaction, manager.tx_storage.get_transaction(tx_hash))

    txin = manager.rng.choice(tx.inputs)

    from hathor.transaction.scripts import P2PKH, parse_address_script
    spent_tx = tx.get_spent_tx(txin)
    spent_txout = spent_tx.outputs[txin.index]
    p2pkh = parse_address_script(spent_txout.script)
    assert isinstance(p2pkh, P2PKH)

    from hathor.wallet.base_wallet import WalletInputInfo, WalletOutputInfo
    value = spent_txout.value
    wallet = manager.wallet
    assert wallet is not None
    private_key = wallet.get_private_key(p2pkh.address)
    inputs = [WalletInputInfo(tx_id=txin.tx_id, index=txin.index, private_key=private_key)]

    address = wallet.get_unused_address(mark_as_used=True)
    outputs = [WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None)]

    tx2 = wallet.prepare_transaction(Transaction, inputs, outputs)
    tx2.storage = manager.tx_storage
    tx2.weight = weight
    tx2.timestamp = max(tx.timestamp + 1, int(manager.reactor.seconds()))

    if use_same_parents:
        tx2.parents = list(tx.parents)
    else:
        tx2.parents = manager.get_new_tx_parents(tx2.timestamp)

    tx2.resolve()
    return tx2
