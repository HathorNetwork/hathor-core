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
    TRANSACTION_VOIDING_CHAIN = 'TRANSACTION_VOIDING_CHAIN'
    VOIDED_TOKEN_AUTHORITY = 'VOIDED_TOKEN_AUTHORITY'

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
            Scenario.TRANSACTION_VOIDING_CHAIN: simulate_transaction_voiding_chain,
            Scenario.VOIDED_TOKEN_AUTHORITY: simulate_voided_token_authority,
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

    balance_per_address = manager.wallet.get_balance_per_address(
        settings.HATHOR_TOKEN_UID)
    assert balance_per_address[address] == 6400
    tx = gen_new_tx(manager, address, 1000)
    tx.weight = manager.daa.minimum_tx_weight(tx)
    tx.update_hash()
    assert manager.propagate_tx(tx)
    simulator.run(60)
    balance_per_address = manager.wallet.get_balance_per_address(
        settings.HATHOR_TOKEN_UID)
    assert balance_per_address[address] == 1000

    # re-org: replace last two blocks with one block, new height will be just one short of enough
    block_to_replace = blocks[-2]
    tb0 = manager.make_custom_block_template(
        block_to_replace.parents[0], block_to_replace.parents[1:])
    b0: Block = tb0.generate_mining_block(
        manager.rng, storage=manager.tx_storage)
    b0.weight = 10
    manager.cpu_mining_service.resolve(b0)
    assert manager.propagate_tx(b0)
    simulator.run(60)

    # the transaction should have been removed from the mempool and the storage after the re-org
    assert tx not in manager.tx_storage.iter_mempool_from_best_index()
    assert not manager.tx_storage.transaction_exists(tx.hash)
    assert bool(tx.get_metadata().voided_by)
    balance_per_address = manager.wallet.get_balance_per_address(
        settings.HATHOR_TOKEN_UID)
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
    tx2.inputs = [TxInput(tx_id=tx1.hash, index=1,
                          data=bytes([len(some_data)]) + some_data)]
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
            self.syscall.call_public_method(contract_id, 'some_method', [])

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
    manager.tx_storage.nc_catalog = NCBlueprintCatalog(
        {blueprint1_id: TestEventsBlueprint1})
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


def simulate_transaction_voiding_chain(
    simulator: 'Simulator',
    manager: 'HathorManager',
) -> Optional['DAGArtifacts']:
    """
    Demonstrates transaction voiding through weight-based conflict resolution.

    Steps:
    1. Setup wallet and generate blocks for funding
    2. Create initial transactions for establishing UTXOs
    3. Create a spending transaction
    4. Create a conflicting transaction with higher weight
    5. Confirm the winning (voiding) transaction
    """
    from hathor.conf.get_settings import get_global_settings
    from hathor.crypto.util import decode_address
    from hathor.simulator.utils import add_new_blocks, gen_new_tx
    from hathor.wallet import HDWallet

    # Constants
    SIMULATION_STEP_DURATION = 60
    TX1_AMOUNT = 1000
    TX2_AMOUNT = 2000
    SPENDING_AMOUNT = 500
    WEIGHT_CONFLICT_DELTA = 0.1
    CONFIRMATION_BLOCKS = 1

    settings = get_global_settings()
    assert manager.wallet is not None
    assert isinstance(manager.wallet, HDWallet)

    wallet = manager.wallet
    address = wallet.get_address(wallet.get_key_at_index(0))
    address_bytes = decode_address(address)

    # Initialize blockchain with funding blocks
    funding_blocks = add_new_blocks(
        manager,
        settings.REWARD_SPEND_MIN_BLOCKS + 1,
        address=address_bytes
    )
    for block in funding_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Create and confirm initial transactions
    tx1 = gen_new_tx(manager, address, TX1_AMOUNT)
    tx1.weight = manager.daa.minimum_tx_weight(tx1)
    tx1.update_hash()
    assert manager.propagate_tx(tx1)
    wallet.on_new_tx(tx1)
    simulator.run(SIMULATION_STEP_DURATION)

    tx2 = gen_new_tx(manager, address, TX2_AMOUNT)
    tx2.weight = manager.daa.minimum_tx_weight(tx2)
    tx2.update_hash()
    assert manager.propagate_tx(tx2)
    wallet.on_new_tx(tx2)
    simulator.run(SIMULATION_STEP_DURATION)

    # Confirm initial transactions
    confirmation_blocks = add_new_blocks(
        manager, CONFIRMATION_BLOCKS, address=address_bytes)
    for block in confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Create spending transaction
    spending_tx = gen_new_tx(manager, address, SPENDING_AMOUNT)
    spending_tx.weight = manager.daa.minimum_tx_weight(spending_tx)
    spending_tx.update_hash()
    assert manager.propagate_tx(spending_tx)
    wallet.on_new_tx(spending_tx)
    simulator.run(SIMULATION_STEP_DURATION)

    # Confirm spending transaction
    spending_confirmation_blocks = add_new_blocks(
        manager, CONFIRMATION_BLOCKS, address=address_bytes)
    for block in spending_confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Create conflicting voiding transaction with higher weight
    voiding_tx = spending_tx.clone(include_metadata=False)
    voiding_tx.timestamp = spending_tx.timestamp + 1
    voiding_tx.weight = spending_tx.weight + WEIGHT_CONFLICT_DELTA
    voiding_tx.update_hash()
    assert manager.propagate_tx(voiding_tx)
    wallet.on_new_tx(voiding_tx)
    simulator.run(SIMULATION_STEP_DURATION)

    # Confirm the voiding transaction
    voiding_confirmation_blocks = add_new_blocks(
        manager, CONFIRMATION_BLOCKS, address=address_bytes)
    for block in voiding_confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    return None


def simulate_voided_token_authority(
    simulator: 'Simulator',
    manager: 'HathorManager',
) -> Optional['DAGArtifacts']:
    """
    Demonstrates token authority voiding through conflicting transactions.

    Creates a custom token with mint/melt authorities, attempts to transfers
    mint authority to another address, then voids that transfer with a
    higher-weight conflicting transaction.
    """
    from hathor.conf.get_settings import get_global_settings
    from hathor.crypto.util import decode_address
    from hathor.simulator.utils import add_new_blocks
    from hathor.transaction import Transaction, TxInput, TxOutput
    from hathor.transaction.scripts import P2PKH
    from hathor.transaction.token_creation_tx import TokenCreationTransaction
    from hathor.wallet import HDWallet

    # Constants
    SIMULATION_STEP_DURATION = 60
    TOKEN_DEPOSIT_AMOUNT = 10
    TOKEN_MINT_AMOUNT = 1000
    TOKEN_NAME = 'TKA'
    TOKEN_SYMBOL = 'TKA'
    AUTHORITY_TRANSFER_WEIGHT = 19.0
    VOIDING_TRANSACTION_WEIGHT = 25.0
    TOKEN_INDEX = 1
    INITIAL_CONFIRMATION_BLOCKS = 1
    AUTHORITY_CONFIRMATION_BLOCKS = 3
    FINAL_CONFIRMATION_BLOCKS = 7

    settings = get_global_settings()
    assert manager.wallet is not None
    assert isinstance(manager.wallet, HDWallet)

    wallet = manager.wallet

    # Get wallet addresses for different roles
    authority_holder_address = wallet.get_address(wallet.get_key_at_index(0))
    transfer_target_address = wallet.get_address(wallet.get_key_at_index(1))
    voiding_target_address = wallet.get_address(wallet.get_key_at_index(2))

    # Setup funding blocks
    funding_blocks = add_new_blocks(
        manager,
        settings.REWARD_SPEND_MIN_BLOCKS + 1,
        address=decode_address(authority_holder_address)
    )
    for block in funding_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Create token outputs
    authority_holder_bytes = decode_address(authority_holder_address)
    authority_holder_script = P2PKH.create_output_script(
        authority_holder_bytes)

    token_outputs = [
        # Minted tokens
        TxOutput(
            value=TOKEN_MINT_AMOUNT,
            script=authority_holder_script,
            token_data=TOKEN_INDEX
        ),
        # Mint authority
        TxOutput(
            value=TxOutput.TOKEN_MINT_MASK,
            script=authority_holder_script,
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | TOKEN_INDEX
        ),
        # Melt authority
        TxOutput(
            value=TxOutput.TOKEN_MELT_MASK,
            script=authority_holder_script,
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | TOKEN_INDEX
        )
    ]

    # Get inputs and handle change
    inputs_info, total_input_amount = wallet.get_inputs_from_amount(
        TOKEN_DEPOSIT_AMOUNT,
        manager.tx_storage,
        settings.HATHOR_TOKEN_UID
    )

    token_inputs = [
        TxInput(
            tx_id=input_info.tx_id,
            index=input_info.index,
            data=b''
        ) for input_info in inputs_info
    ]

    # Add change output if necessary
    change_value = total_input_amount - TOKEN_DEPOSIT_AMOUNT
    if change_value > 0:
        token_outputs.append(TxOutput(
            value=change_value,
            script=authority_holder_script,
            token_data=0  # HTR
        ))

    # Create and sign token creation transaction
    token_creation_tx = TokenCreationTransaction(
        inputs=token_inputs,
        outputs=token_outputs,
        parents=manager.get_new_tx_parents(),
        token_name=TOKEN_NAME,
        token_symbol=TOKEN_SYMBOL,
        storage=manager.tx_storage,
        timestamp=int(manager.reactor.seconds())
    )

    # Sign token creation transaction
    data_to_sign = token_creation_tx.get_sighash_all()
    private_key = wallet.get_private_key(authority_holder_address)

    for i, _ in enumerate(token_creation_tx.inputs):
        public_key_bytes, signature = wallet.get_input_aux_data(
            data_to_sign, private_key)
        token_creation_tx.inputs[i].data = P2PKH.create_input_data(
            public_key_bytes, signature)

    # Propagate token creation
    token_creation_tx.weight = manager.daa.minimum_tx_weight(token_creation_tx)
    token_creation_tx.update_hash()
    assert manager.propagate_tx(token_creation_tx)
    wallet.on_new_tx(token_creation_tx)
    simulator.run(SIMULATION_STEP_DURATION)

    # Confirm token creation
    token_confirmation_blocks = add_new_blocks(
        manager, INITIAL_CONFIRMATION_BLOCKS,
        address=decode_address(authority_holder_address)
    )
    for block in token_confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Find mint authority output index
    mint_authority_index = None
    for i, output in enumerate(token_creation_tx.outputs):
        if output.value == TxOutput.TOKEN_MINT_MASK:
            mint_authority_index = i
            break

    assert mint_authority_index is not None, "Could not find mint authority output"

    # Create authority transfer transaction
    transfer_target_bytes = decode_address(transfer_target_address)
    transfer_target_script = P2PKH.create_output_script(transfer_target_bytes)

    authority_transfer_tx = Transaction(
        inputs=[TxInput(
            tx_id=token_creation_tx.hash,
            index=mint_authority_index,
            data=b''
        )],
        outputs=[TxOutput(
            value=TxOutput.TOKEN_MINT_MASK,
            script=transfer_target_script,
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | TOKEN_INDEX
        )],
        tokens=[token_creation_tx.hash],
        weight=AUTHORITY_TRANSFER_WEIGHT,
        parents=manager.get_new_tx_parents(),
        storage=manager.tx_storage,
        timestamp=int(manager.reactor.seconds())
    )

    # Create conflicting voiding transaction
    voiding_target_bytes = decode_address(voiding_target_address)
    voiding_target_script = P2PKH.create_output_script(voiding_target_bytes)

    voiding_authority_tx = Transaction(
        inputs=[TxInput(
            tx_id=token_creation_tx.hash,
            index=mint_authority_index,
            data=b''
        )],
        outputs=[TxOutput(
            value=TxOutput.TOKEN_MINT_MASK,
            script=voiding_target_script,
            token_data=TxOutput.TOKEN_AUTHORITY_MASK | TOKEN_INDEX
        )],
        tokens=[token_creation_tx.hash],
        weight=VOIDING_TRANSACTION_WEIGHT,
        parents=manager.get_new_tx_parents(),
        storage=manager.tx_storage,
        timestamp=int(manager.reactor.seconds())
    )

    # Sign both authority transactions
    for tx in [authority_transfer_tx, voiding_authority_tx]:
        data_to_sign = tx.get_sighash_all()
        public_key_bytes, signature = wallet.get_input_aux_data(
            data_to_sign, private_key)
        tx.inputs[0].data = P2PKH.create_input_data(
            public_key_bytes, signature)
        manager.cpu_mining_service.resolve(tx)

    # Propagate authority transfer first
    manager.propagate_tx(authority_transfer_tx)

    # Add blocks to establish authority transfer
    authority_confirmation_blocks = add_new_blocks(
        manager, AUTHORITY_CONFIRMATION_BLOCKS,
        address=decode_address(authority_holder_address)
    )
    for block in authority_confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    # Propagate voiding transaction
    manager.propagate_tx(voiding_authority_tx)
    simulator.run(SIMULATION_STEP_DURATION)

    # Final confirmation blocks to resolve the conflict
    final_confirmation_blocks = add_new_blocks(
        manager, FINAL_CONFIRMATION_BLOCKS,
        address=decode_address(authority_holder_address)
    )
    for block in final_confirmation_blocks:
        wallet.on_new_tx(block)
    simulator.run(SIMULATION_STEP_DURATION)

    return None


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
