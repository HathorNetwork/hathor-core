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
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from hathor.dag_builder import DAGBuilder
    from hathor.dag_builder.artifacts import DAGArtifacts
    from hathor.manager import HathorManager
    from hathor.simulator import Simulator


class Scenario(Enum):
    ONLY_LOAD = 'ONLY_LOAD'
    SINGLE_CHAIN_ONE_BLOCK = 'SINGLE_CHAIN_ONE_BLOCK'
    SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS = 'SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS'
    REORG = 'REORG'
    UNVOIDED_TRANSACTION = 'UNVOIDED_TRANSACTION'
    INVALID_MEMPOOL_TRANSACTION = 'INVALID_MEMPOOL_TRANSACTION'
    EMPTY_SCRIPT = 'EMPTY_SCRIPT'
    CUSTOM_SCRIPT = 'CUSTOM_SCRIPT'
    NC_EVENTS = 'NC_EVENTS'
    NC_EVENTS_REORG = 'NC_EVENTS_REORG'

    def simulate(self, simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
        simulate_fns = {
            Scenario.ONLY_LOAD: simulate_only_load,
            Scenario.SINGLE_CHAIN_ONE_BLOCK: simulate_single_chain_one_block,
            Scenario.SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS: simulate_single_chain_blocks_and_transactions,
            Scenario.REORG: simulate_reorg,
            Scenario.UNVOIDED_TRANSACTION: simulate_unvoided_transaction,
            Scenario.INVALID_MEMPOOL_TRANSACTION: simulate_invalid_mempool_transaction,
            Scenario.EMPTY_SCRIPT: simulate_empty_script,
            Scenario.CUSTOM_SCRIPT: simulate_custom_script,
            Scenario.NC_EVENTS: simulate_nc_events,
            Scenario.NC_EVENTS_REORG: simulate_nc_events_reorg,
        }

        simulate_fn = simulate_fns[self]

        return simulate_fn(simulator, manager)

    def get_reward_spend_min_blocks(self) -> int:
        """Get the REWARD_SPEND_MIN_BLOCKS settings required for this scenario."""
        return 1 if self in (Scenario.NC_EVENTS, Scenario.NC_EVENTS_REORG) else 10


def simulate_only_load(simulator: 'Simulator', _manager: 'HathorManager') -> Optional['DAGArtifacts']:
    simulator.run(60)
    return None


def simulate_single_chain_one_block(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.simulator.utils import add_new_blocks
    add_new_blocks(manager, 1)
    simulator.run(60)
    return None


def simulate_single_chain_blocks_and_transactions(
    simulator: 'Simulator',
    manager: 'HathorManager',
) -> Optional['DAGArtifacts']:
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
    assert manager.propagate_tx(tx)
    simulator.run(60)

    tx = gen_new_tx(manager, address, 2000)
    tx.weight = manager.daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx)
    simulator.run(60)

    add_new_blocks(manager, 1)
    simulator.run(60)

    return None


def simulate_reorg(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
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

    return None


def simulate_unvoided_transaction(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
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
    assert manager.propagate_tx(tx)
    simulator.run(60)

    # A clone is created with a greater timestamp and a lower weight. It's a voided twin tx.
    tx2 = tx.clone(include_metadata=False)
    tx2.timestamp += 60
    tx2.weight = 19
    tx2.update_hash()
    assert manager.propagate_tx(tx2)
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
    assert manager.propagate_tx(block)
    simulator.run(60)

    # The first tx gets voided and the second gets unvoided
    assert tx.get_metadata().voided_by
    assert not tx2.get_metadata().voided_by

    return None


def simulate_invalid_mempool_transaction(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.simulator.utils import add_new_blocks, gen_new_tx
    from hathor.transaction import Block

    settings = manager._settings
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address(mark_as_used=False)

    blocks = add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    balance_per_address = manager.wallet.get_balance_per_address(settings.HATHOR_TOKEN_UID)
    assert balance_per_address[address] == 6400
    tx = gen_new_tx(manager, address, 1000)
    tx.weight = manager.daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx)
    simulator.run(60)
    balance_per_address = manager.wallet.get_balance_per_address(settings.HATHOR_TOKEN_UID)
    assert balance_per_address[address] == 1000

    # re-org: replace last two blocks with one block, new height will be just one short of enough
    block_to_replace = blocks[-2]
    tb0 = manager.make_custom_block_template(block_to_replace.parents[0], block_to_replace.parents[1:])
    b0: Block = tb0.generate_mining_block(manager.rng, storage=manager.tx_storage)
    b0.weight = 10
    manager.cpu_mining_service.resolve(b0)
    assert manager.propagate_tx(b0)
    simulator.run(60)

    # the transaction should have been removed from the mempool and the storage after the re-org
    assert tx not in manager.tx_storage.iter_mempool()
    assert not manager.tx_storage.transaction_exists(tx.hash)
    assert bool(tx.get_metadata().voided_by)
    balance_per_address = manager.wallet.get_balance_per_address(settings.HATHOR_TOKEN_UID)
    assert balance_per_address[address] == 6400

    return None


def simulate_empty_script(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.conf.get_settings import get_global_settings
    from hathor.simulator.utils import add_new_blocks, gen_new_tx
    from hathor.transaction import TxInput, TxOutput

    settings = get_global_settings()
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address(mark_as_used=False)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    tx1 = gen_new_tx(manager, address, 1000)
    original_script = tx1.outputs[1].script
    tx1.outputs[1].script = b''
    tx1.weight = manager.daa.minimum_tx_weight(tx1)
    tx1.update_hash()
    assert manager.propagate_tx(tx1)
    simulator.run(60)

    tx2 = gen_new_tx(manager, address, 1000)
    tx2.inputs = [TxInput(tx_id=tx1.hash, index=1, data=b'\x51')]
    tx2.outputs = [TxOutput(value=1000, script=original_script)]
    tx2.weight = manager.daa.minimum_tx_weight(tx2)
    tx2.update_hash()
    assert manager.propagate_tx(tx2)
    simulator.run(60)

    add_new_blocks(manager, 1)
    simulator.run(60)

    return None


def simulate_custom_script(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.conf.get_settings import get_global_settings
    from hathor.simulator.utils import add_new_blocks, gen_new_tx
    from hathor.transaction import TxInput, TxOutput
    from hathor.transaction.scripts import HathorScript, Opcode

    settings = get_global_settings()
    assert manager.wallet is not None
    address = manager.wallet.get_unused_address()

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    tx1 = gen_new_tx(manager, address, 1000)
    s = HathorScript()
    some_data = b'some_data'
    s.pushData(some_data)
    s.addOpcode(Opcode.OP_EQUALVERIFY)
    s.addOpcode(Opcode.OP_1)
    original_script = tx1.outputs[1].script
    tx1.outputs[1].script = s.data
    tx1.weight = manager.daa.minimum_tx_weight(tx1)
    tx1.update_hash()
    assert manager.propagate_tx(tx1)
    simulator.run(60)

    tx2 = gen_new_tx(manager, address, 1000)
    tx2.inputs = [TxInput(tx_id=tx1.hash, index=1, data=bytes([len(some_data)]) + some_data)]
    tx2.outputs = [TxOutput(value=1000, script=original_script)]
    tx2.weight = manager.daa.minimum_tx_weight(tx2)
    tx2.update_hash()
    assert manager.propagate_tx(tx2)
    simulator.run(60)

    add_new_blocks(manager, 1)
    simulator.run(60)

    return None


def simulate_nc_events(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.nanocontracts import Blueprint, NCFail, public
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.context import Context
    from hathor.nanocontracts.types import ContractId

    class TestEventsBlueprint1(Blueprint):
        @public
        def initialize(self, ctx: Context) -> None:
            self.syscall.emit_event(b'test event on initialize 1')

        @public
        def fail(self, ctx: Context) -> None:
            # This will not be emitted because the tx will fail.
            self.syscall.emit_event(b'test event on fail')
            raise NCFail

        @public
        def call_another(self, ctx: Context, contract_id: ContractId) -> None:
            self.syscall.emit_event(b'test event on call_another')
            self.syscall.get_contract(contract_id, blueprint_id=None).public().some_method()

    class TestEventsBlueprint2(Blueprint):
        @public
        def initialize(self, ctx: Context) -> None:
            self.syscall.emit_event(b'test event on initialize 2')

        @public
        def some_method(self, ctx: Context) -> None:
            self.syscall.emit_event(b'test event on some_method')

    blueprint1_id = b'\x11' * 32
    blueprint2_id = b'\x22' * 32
    manager.tx_storage.nc_catalog = NCBlueprintCatalog({
        blueprint1_id: TestEventsBlueprint1,
        blueprint2_id: TestEventsBlueprint2,
    })
    dag_builder = _create_dag_builder(manager)
    artifacts = dag_builder.build_from_str(f'''
        blockchain genesis b[1..3]
        b1 < dummy

        # test simple event
        nc1.nc_id = "{blueprint1_id.hex()}"
        nc1.nc_method = initialize()

        nc2.nc_id = "{blueprint2_id.hex()}"
        nc2.nc_method = initialize()

        # test events across contracts
        nc3.nc_id = nc1
        nc3.nc_method = call_another(`nc2`)

        # test NC failure
        nc4.nc_id = nc1
        nc4.nc_method = fail()

        nc1 <-- nc2 <-- nc3 <-- nc4
        nc2 <-- b2
        nc4 <-- b3
        nc4 < b2
    ''')
    artifacts.propagate_with(manager, up_to='b2')
    simulator.run(1)
    artifacts.propagate_with(manager)
    simulator.run(1)

    return artifacts


def simulate_nc_events_reorg(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.nanocontracts import Blueprint, public
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.context import Context

    class TestEventsBlueprint1(Blueprint):
        @public
        def initialize(self, ctx: Context) -> None:
            self.syscall.emit_event(b'test event on initialize 1')

    blueprint1_id = b'\x11' * 32
    manager.tx_storage.nc_catalog = NCBlueprintCatalog({blueprint1_id: TestEventsBlueprint1})
    dag_builder = _create_dag_builder(manager)

    # 2 reorgs happen, so nc1.initialize() gets executed 3 times, once in block a2 and twice in block b2
    artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..4]
            blockchain b1 a[2..3]
            b1 < dummy
            b2 < a2 < a3 < b3 < b4

            nc1.nc_id = "{blueprint1_id.hex()}"
            nc1.nc_method = initialize()

            nc1 <-- b2
            nc1 <-- a2
    ''')

    artifacts.propagate_with(manager)
    simulator.run(1)

    return artifacts


def _create_dag_builder(manager: 'HathorManager') -> 'DAGBuilder':
    from mnemonic import Mnemonic

    from hathor.dag_builder import DAGBuilder
    from hathor.wallet import HDWallet

    seed = ('coral light army gather adapt blossom school alcohol coral light army gather '
            'adapt blossom school alcohol coral light army gather adapt blossom school awesome')

    def create_random_hd_wallet() -> HDWallet:
        m = Mnemonic('english')
        words = m.to_mnemonic(manager.rng.randbytes(32))
        hd = HDWallet(words=words)
        hd._manually_initialize()
        return hd

    return DAGBuilder.from_manager(
        manager=manager,
        genesis_words=seed,
        wallet_factory=create_random_hd_wallet,
    )
