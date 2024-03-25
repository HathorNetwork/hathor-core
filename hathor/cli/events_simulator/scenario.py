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

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.simulator import Simulator


class Scenario(Enum):
    ONLY_LOAD = 'ONLY_LOAD'
    SINGLE_CHAIN_ONE_BLOCK = 'SINGLE_CHAIN_ONE_BLOCK'
    SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS = 'SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS'
    REORG = 'REORG'
    UNVOIDED_TRANSACTION = 'UNVOIDED_TRANSACTION'

    def simulate(self, simulator: 'Simulator', manager: 'HathorManager') -> None:
        simulate_fns = {
            Scenario.ONLY_LOAD: simulate_only_load,
            Scenario.SINGLE_CHAIN_ONE_BLOCK: simulate_single_chain_one_block,
            Scenario.SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS: simulate_single_chain_blocks_and_transactions,
            Scenario.REORG: simulate_reorg,
            Scenario.UNVOIDED_TRANSACTION: simulate_unvoided_transaction,
        }

        simulate_fn = simulate_fns[self]

        simulate_fn(simulator, manager)


def simulate_only_load(simulator: 'Simulator', _manager: 'HathorManager') -> None:
    simulator.run(60)


def simulate_single_chain_one_block(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.simulator.utils import add_new_blocks
    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_single_chain_blocks_and_transactions(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.conf.get_settings import get_global_settings
    from hathor.simulator.utils import add_new_blocks, gen_new_tx

    settings = get_global_settings()
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address(mark_as_used=False)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    tx = gen_new_tx(manager, address, 1000)
    tx.weight = manager.daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx, fails_silently=False)
    simulator.run(60)

    tx = gen_new_tx(manager, address, 2000)
    tx.weight = manager.daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx, fails_silently=False)
    simulator.run(60)

    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_reorg(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.simulator import FakeConnection
    from hathor.simulator.utils import add_new_blocks

    builder = simulator.get_default_builder()
    manager2 = simulator.create_peer(builder)

    add_new_blocks(manager, 1)
    simulator.run(60)

    add_new_blocks(manager2, 2)
    simulator.run(60)

    connection = FakeConnection(manager, manager2)
    simulator.add_connection(connection)
    simulator.run(60)


def simulate_unvoided_transaction(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.conf.get_settings import get_global_settings
    from hathor.simulator.utils import add_new_block, add_new_blocks, gen_new_tx

    settings = get_global_settings()
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address(mark_as_used=False)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    # A tx is created with weight 19.0005
    tx = gen_new_tx(manager, address, 1000)
    tx.weight = 19.0005
    tx.update_hash()
    assert manager.propagate_tx(tx, fails_silently=False)
    simulator.run(60)

    # A clone is created with a greater timestamp and a lower weight. It's a voided twin tx.
    tx2 = tx.clone(include_metadata=False)
    tx2.timestamp += 60
    tx2.weight = 19
    tx2.update_hash()
    assert manager.propagate_tx(tx2, fails_silently=False)
    simulator.run(60)

    # Only the second tx is voided
    assert not tx.get_metadata().voided_by
    assert tx2.get_metadata().voided_by

    # We add a block confirming the second tx, increasing its acc weight
    block = add_new_block(manager, propagate=False)
    block.parents = [
        block.parents[0],
        settings.GENESIS_TX1_HASH,
        tx2.hash,
    ]
    block.update_hash()
    assert manager.propagate_tx(block, fails_silently=False)
    simulator.run(60)

    # The first tx gets voided and the second gets unvoided
    assert tx.get_metadata().voided_by
    assert not tx2.get_metadata().voided_by
