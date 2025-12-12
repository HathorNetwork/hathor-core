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

from typing import Optional, cast

from hathor.crypto.util import decode_address
from hathor.manager import HathorManager
from hathor.transaction import Block, Transaction
from hathor.types import Address, VertexId


def gen_new_tx(manager: HathorManager, address: str, value: int) -> Transaction:
    """
    Generate and return a new transaction.

    Args:
        manager: the HathorManager to generate the transaction for
        address: an address for the transaction's output
        value: a value for the transaction's output

    Returns: the generated transaction.
    """
    from hathor.transaction import Transaction
    from hathor.wallet.base_wallet import WalletOutputInfo

    outputs = []
    outputs.append(WalletOutputInfo(address=decode_address(address), value=int(value), timelock=None))

    assert manager.wallet is not None
    tx = manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, manager.tx_storage)
    tx.storage = manager.tx_storage

    max_ts_spent_tx = max(tx.get_spent_tx(txin).timestamp for txin in tx.inputs)
    tx.timestamp = max(max_ts_spent_tx + 1, manager.get_timestamp_for_new_vertex())

    tx.weight = 1
    tx.parents = manager.get_new_tx_parents(tx.timestamp)
    manager.cpu_mining_service.resolve(tx)
    return tx


def add_new_blocks(
    manager: HathorManager,
    num_blocks: int,
    advance_clock: Optional[int] = None,
    *,
    parent_block_hash: Optional[VertexId] = None,
    block_data: bytes = b'',
    weight: Optional[float] = None,
    address: Optional[Address] = None,
    signal_bits: int | None = None,
) -> list[Block]:
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
                          data=block_data, weight=weight, address=address, signal_bits=signal_bits)
        )
        if parent_block_hash:
            parent_block_hash = blocks[-1].hash
    return blocks


def add_new_block(
    manager: HathorManager,
    advance_clock: Optional[int] = None,
    *,
    parent_block_hash: Optional[VertexId] = None,
    data: bytes = b'',
    weight: Optional[float] = None,
    address: Optional[Address] = None,
    propagate: bool = True,
    signal_bits: int | None = None,
) -> Block:
    """ Create, resolve and propagate a new block

        :param manager: Manager object to handle the creation
        :type manager: :py:class:`hathor.manager.HathorManager`

        :return: Block created
        :rtype: :py:class:`hathor.transaction.block.Block`
    """
    block = manager.generate_mining_block(parent_block_hash=parent_block_hash, data=data, address=address)
    if weight is not None:
        block.weight = weight
    if signal_bits is not None:
        block.signal_bits = signal_bits
    manager.cpu_mining_service.resolve(block)
    if propagate:
        manager.propagate_tx(block)
    if advance_clock:
        assert hasattr(manager.reactor, 'advance')
        manager.reactor.advance(advance_clock)
    return block


class NoCandidatesError(Exception):
    pass


def gen_new_double_spending(manager: HathorManager, *, use_same_parents: bool = False,
                            tx: Optional[Transaction] = None, weight: float = 1) -> Transaction:
    """
    Generate and return a double spending transaction.

    Args:
        manager: the HathorManager to generate the transaction for
        use_same_parents: whether to use the same parents as the original transaction
        tx: the original transaction do double spend
        weight: the new transaction's weight

    Returns: the double spending transaction.
    """
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

    manager.cpu_mining_service.resolve(tx2)
    return tx2
