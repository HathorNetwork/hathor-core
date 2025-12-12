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
    TOKEN_CREATED = 'TOKEN_CREATED'
    TOKEN_CREATED_HYBRID_WITH_REORG = 'TOKEN_CREATED_HYBRID_WITH_REORG'

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
            Scenario.TOKEN_CREATED: simulate_token_created,
            Scenario.TOKEN_CREATED_HYBRID_WITH_REORG: simulate_token_created_hybrid_with_reorg,
        }

        simulate_fn = simulate_fns[self]

        return simulate_fn(simulator, manager)

    def get_reward_spend_min_blocks(self) -> int:
        """Get the REWARD_SPEND_MIN_BLOCKS settings required for this scenario."""
        nc_scenarios = (
            Scenario.NC_EVENTS,
            Scenario.NC_EVENTS_REORG,
            Scenario.TOKEN_CREATED,
            Scenario.TOKEN_CREATED_HYBRID_WITH_REORG,
        )
        return 1 if self in nc_scenarios else 10


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


def simulate_token_created(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    from hathor.nanocontracts import Blueprint, public
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.context import Context

    # Define the NC blueprint for token creation
    class TokenFactoryBlueprint(Blueprint):
        @public(allow_deposit=True)
        def initialize(self, ctx: Context) -> None:
            pass

        @public(allow_deposit=True)
        def create_nc_token(self, ctx: Context) -> None:
            self.syscall.create_deposit_token(
                token_name='NC Token',
                token_symbol='NCT',
                amount=500,
            )

    blueprint_id = b'\xaa' * 32
    manager.tx_storage.nc_catalog = NCBlueprintCatalog({blueprint_id: TokenFactoryBlueprint})

    # Use DAG builder to create BOTH tokens in the same blockchain
    dag_builder = _create_dag_builder(manager)
    artifacts = dag_builder.build_from_str(f'''
        blockchain genesis b[1..10]
        b1 < dummy

        # First, create a regular TokenCreationTransaction (traditional way)
        dummy < RGT < b2

        # Set token metadata for the regular token
        # Create a transaction that uses the RGT token
        tx_regular.out[0] = 300 RGT
        RGT < tx_regular < b3

        # Then create a token via nano contract
        # Create a nano contract with deposit
        nc1.nc_id = "{blueprint_id.hex()}"
        nc1.nc_method = initialize()
        nc1.nc_deposit = 100 HTR
        b5 < nc1

        # Call create_nc_token method with deposit
        nc2.nc_id = nc1
        nc2.nc_method = create_nc_token()
        nc2.nc_deposit = 5 HTR

        # Set up dependencies - nc2 needs to be confirmed by a block
        nc1 < nc2 < b6
        nc1 <-- b6
        nc2 <-- b7
    ''')

    # Propagate everything and give the simulator time to process
    artifacts.propagate_with(manager)
    simulator.run(60)

    return artifacts


def simulate_token_created_hybrid_with_reorg(simulator: 'Simulator', manager: 'HathorManager') -> Optional['DAGArtifacts']:
    """
    Simulates a HYBRID TokenCreationTransaction that:
    1. Creates a token via traditional TokenCreationTransaction
    2. Also has nano contract headers that create another token via syscall
    3. Gets confirmed and both tokens are created (2 TOKEN_CREATED events)
    4. A reorg happens, making the transaction go back to mempool
    5. NC execution goes from SUCCESS → PENDING
    6. NC-created token should be deleted, traditional token remains
    """
    from hathor.nanocontracts import Blueprint, public
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.nanocontracts.context import Context
    from hathor.transaction.nc_execution_state import NCExecutionState

    # Define the NC blueprint for token creation
    class HybridTokenFactoryBlueprint(Blueprint):
        @public(allow_deposit=True)
        def initialize(self, ctx: Context) -> None:
            pass

        @public(allow_deposit=True)
        def create_extra_token(self, ctx: Context) -> None:
            """Creates an additional token via NC syscall"""
            self.syscall.create_deposit_token(
                token_name='NC Extra Token',
                token_symbol='NCX',
                amount=777,
            )

    blueprint_id = b'\xbb' * 32
    manager.tx_storage.nc_catalog = NCBlueprintCatalog({blueprint_id: HybridTokenFactoryBlueprint})

    # Create a reorg scenario with a hybrid transaction
    dag_builder = _create_dag_builder(manager)
    artifacts = dag_builder.build_from_str(f'''
        blockchain genesis b[1..2]
        b1 < dummy

        # Create transactions
        # Initialize the nano contract
        nc_init.nc_id = "{blueprint_id.hex()}"
        nc_init.nc_method = initialize()
        nc_init.nc_deposit = 50 HTR

        # Create a HYBRID transaction (tit) that:
        # 1. Is a TokenCreationTransaction (creates HYB token traditionally)
        # 2. Also has NC headers that call create_extra_token() to create NCX via syscall
        HYB.nc_id = nc_init
        HYB.nc_method = create_extra_token()
        HYB.nc_deposit = 100 HTR
        tit.out[0] = 500 HYB

        # Set up parents
        dummy < nc_init
        nc_init < tit   # tit depends on nc_init

        # Confirm both in b2
        nc_init <-- b2
        tit <-- b2

        # Now create the longer a-chain that will cause a reorg
        blockchain b1 a[2..10]
        a2.weight = 40
        b2 < a2

        # After reorg, both get re-confirmed in a3
        nc_init <-- a5
        # tit <-- a5
        HYB <-- a5
    ''')

    # Propagate all blocks - causes reorg during propagation
    artifacts.propagate_with(manager, up_to='b2')
    b2 = artifacts.by_name['b2'].vertex
    nc_init = artifacts.by_name['nc_init'].vertex
    HYB = artifacts.by_name['HYB'].vertex

    assert not b2.get_metadata().voided_by
    assert not nc_init.get_metadata().voided_by
    assert not HYB.get_metadata().voided_by
    assert nc_init.get_metadata().first_block == b2.hash
    assert HYB.get_metadata().first_block == b2.hash
    assert HYB.get_metadata().nc_execution == NCExecutionState.SUCCESS

    artifacts.propagate_with(manager, up_to='a2')
    a2 = artifacts.by_name['a2'].vertex

    assert not a2.get_metadata().voided_by
    assert b2.get_metadata().voided_by
    assert not nc_init.get_metadata().voided_by
    assert not HYB.get_metadata().voided_by
    assert nc_init.get_metadata().first_block is None
    assert HYB.get_metadata().first_block is None
    assert HYB.get_metadata().nc_execution == NCExecutionState.PENDING

    artifacts.propagate_with(manager)
    a5 = artifacts.by_name['a5'].vertex

    assert not a2.get_metadata().voided_by
    assert not a5.get_metadata().voided_by
    assert b2.get_metadata().voided_by

    assert not nc_init.get_metadata().voided_by
    assert not HYB.get_metadata().voided_by
    assert nc_init.get_metadata().first_block == a5.hash
    assert HYB.get_metadata().first_block == a5.hash
    assert HYB.get_metadata().nc_execution == NCExecutionState.SUCCESS

    simulator.run(1)
    return artifacts


def _create_dag_builder(manager: 'HathorManager') -> 'DAGBuilder':
    from hathor.dag_builder import DAGBuilder
    from hathor.wallet import HDWallet

    seed = ('coral light army gather adapt blossom school alcohol coral light army gather '
            'adapt blossom school alcohol coral light army gather adapt blossom school awesome')

    def create_deterministic_hd_wallet() -> HDWallet:
        hd = HDWallet(words=seed)
        hd._manually_initialize()
        return hd

    return DAGBuilder.from_manager(
        manager=manager,
        genesis_words=seed,
        wallet_factory=create_deterministic_hd_wallet,
    )
