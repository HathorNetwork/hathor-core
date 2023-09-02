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

    def simulate(self, simulator: 'Simulator', manager: 'HathorManager') -> None:
        simulate_fns = {
            Scenario.ONLY_LOAD: simulate_only_load,
            Scenario.SINGLE_CHAIN_ONE_BLOCK: simulate_single_chain_one_block,
            Scenario.SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS: simulate_single_chain_blocks_and_transactions,
            Scenario.REORG: simulate_reorg,
        }

        simulate_fn = simulate_fns[self]

        simulate_fn(simulator, manager)


def simulate_only_load(simulator: 'Simulator', _manager: 'HathorManager') -> None:
    simulator.run(60)


def simulate_single_chain_one_block(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from tests.utils import add_new_blocks
    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_single_chain_blocks_and_transactions(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor import daa
    from hathor.conf import get_settings
    from tests.utils import add_new_blocks, gen_new_tx

    settings = get_settings()
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address(mark_as_used=False)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    tx = gen_new_tx(manager, address, 1000)
    tx.weight = daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx, fails_silently=False)
    simulator.run(60)

    tx = gen_new_tx(manager, address, 2000)
    tx.weight = daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx, fails_silently=False)
    simulator.run(60)

    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_reorg(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.simulator import FakeConnection
    from tests.utils import add_new_blocks

    builder = simulator.get_default_builder()
    manager2 = simulator.create_peer(builder)

    add_new_blocks(manager, 1)
    simulator.run(60)

    add_new_blocks(manager2, 2)
    simulator.run(60)

    connection = FakeConnection(manager, manager2)
    simulator.add_connection(connection)
    simulator.run(60)
