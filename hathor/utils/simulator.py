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
from hathor.transaction import Transaction


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
