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
    CUSTOM_TOKEN_TRANSACTIONS = 'CUSTOM_TOKEN_TRANSACTIONS'
    VOID_CREATE_TOKEN_INPUT = 'VOID_CREATE_TOKEN_INPUT'

    def simulate(self, simulator: 'Simulator', manager: 'HathorManager') -> None:
        simulate_fns = {
            Scenario.ONLY_LOAD: simulate_only_load,
            Scenario.SINGLE_CHAIN_ONE_BLOCK: simulate_single_chain_one_block,
            Scenario.SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS: simulate_single_chain_blocks_and_transactions,
            Scenario.REORG: simulate_reorg,
            Scenario.CUSTOM_TOKEN_TRANSACTIONS: simulate_custom_token_transactions,
            Scenario.VOID_CREATE_TOKEN_INPUT: simulate_void_create_token_input
        }

        simulate_fn = simulate_fns[self]

        simulate_fn(simulator, manager)


def simulate_only_load(simulator: 'Simulator', _manager: 'HathorManager') -> None:
    simulator.run(60)


def simulate_single_chain_one_block(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor.utils.simulator import add_new_blocks
    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_single_chain_blocks_and_transactions(simulator: 'Simulator', manager: 'HathorManager') -> None:
    from hathor import daa
    from hathor.conf import HathorSettings
    from hathor.utils.simulator import add_new_blocks, gen_new_tx

    settings = HathorSettings()
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
    from hathor.utils.simulator import add_new_blocks

    builder = simulator.get_default_builder()
    manager2 = simulator.create_peer(builder)

    add_new_blocks(manager, 1)
    simulator.run(60)

    add_new_blocks(manager2, 2)
    simulator.run(60)

    connection = FakeConnection(manager, manager2)
    simulator.add_connection(connection)
    simulator.run(60)


def simulate_custom_token_transactions(simulator: 'Simulator',
                                       manager: 'HathorManager') -> None:
    from hathor import daa
    from hathor.conf import HathorSettings
    from hathor.utils.simulator import add_new_blocks
    from hathor.crypto.util import decode_address
    from hathor.wallet import Wallet
    from hathor.utils.simulator import create_tokens
    from hathor.transaction import (Transaction,
                                    TxInput, TxOutput)
    from hathor.transaction.scripts import P2PKH
    from typing import Optional
    from cryptography.hazmat.backends.openssl.ec import (
                _EllipticCurvePrivateKey
            )

    def create_tx(
        *,
        manager: 'HathorManager',
        wallet: Wallet,
        input_address: str,
        tokens: list[bytes],
        inputs: list[TxInput],
        outputs: list[TxOutput],
        propagate: bool,
        parents: Optional[list[bytes]] = None,
        private_key: Optional[_EllipticCurvePrivateKey] = None,
    ) -> Transaction:
        tx = Transaction(
            weight=22,
            tokens=tokens,
            timestamp=int(manager.reactor.seconds()) + 1,
            inputs=inputs,
            outputs=outputs,
            parents=parents or manager.get_new_tx_parents(),
            storage=manager.tx_storage,
        )

        data_to_sign = tx.get_sighash_all()
        private_key = private_key or wallet.get_private_key(input_address)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign,
                                                            private_key)

        for tx_input in inputs:
            tx_input.data = P2PKH.create_input_data(public_bytes, signature)

        tx.resolve()
        tx.update_initial_metadata(save=False)

        if propagate:
            propagated = manager.on_new_tx(tx, fails_silently=False)

            assert propagated
        return tx

    settings = HathorSettings()
    assert manager.wallet is not None

    wallet = Wallet()
    wallet.unlock(b'MYPASS')
    wallet.generate_keys()
    wallet_address = wallet.get_unused_address()
    wallet_address2 = wallet.get_unused_address()

    manager.wallet = wallet
    # wallet_address_bytes = decode_address(wallet_address)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)
    simulator.run(60)

    token_creation_tx = create_tokens(manager, wallet_address, 50,
                                      'TEST', 'TEST', False)
    token_creation_tx.weight = daa.minimum_tx_weight(token_creation_tx)
    token_creation_tx.update_hash()

    print("token_creation_tx", token_creation_tx.hash_hex)

    assert manager.propagate_tx(token_creation_tx, fails_silently=False)

    # delegate (mint|melt) to another address
    # (mint|melt) token
    # destroy authority (mint|melt)

    # Delegate Mint ---

    delegate_mint_inputs = [TxInput(token_creation_tx.hash, 1, b'')]
    delegate_mint_change_authority_script = P2PKH.create_output_script(
            decode_address(wallet_address))
    delegate_mint_receiver_authority_script = P2PKH.create_output_script(
            decode_address(wallet_address2))
    delegate_mint_outputs = [
            # TxOutput(value: int, script: TxOutputScript, token_data: int=0)
            TxOutput(0b0000_0001,
                     delegate_mint_change_authority_script,
                     TxOutput.TOKEN_AUTHORITY_MASK | 1),
            TxOutput(0b0000_0001,
                     delegate_mint_receiver_authority_script,
                     TxOutput.TOKEN_AUTHORITY_MASK | 1),
            ]
    delegate_mint_tx = create_tx(manager=manager,
                                 input_address=wallet_address,
                                 wallet=manager.wallet,
                                 tokens=[token_creation_tx.hash],
                                 inputs=delegate_mint_inputs,
                                 propagate=False,
                                 outputs=delegate_mint_outputs)

    print("delegate_mint_tx", delegate_mint_tx.hash_hex)

    assert manager.propagate_tx(delegate_mint_tx, fails_silently=False)

    add_new_blocks(manager, 1)
    simulator.run(60)


def simulate_void_create_token_input(simulator: 'Simulator',
                                     manager: 'HathorManager') -> None:
    from hathor.simulator import FakeConnection
    from hathor import daa
    from hathor.conf import HathorSettings
    from hathor.utils.simulator import add_new_blocks
    from hathor.wallet import Wallet
    from hathor.utils.simulator import create_tokens

    builder = simulator.get_default_builder()
    manager2 = simulator.create_peer(builder)

    settings = HathorSettings()
    assert manager.wallet is not None

    wallet = Wallet()
    wallet.unlock(b'MYPASS')
    wallet.generate_keys()
    wallet_address = wallet.get_unused_address()

    manager.wallet = wallet

    add_new_blocks(manager2, settings.REWARD_SPEND_MIN_BLOCKS + 15)

    simulator.run(60)

    add_new_blocks(manager, settings.REWARD_SPEND_MIN_BLOCKS + 1)

    simulator.run(60)

    token_creation_tx = create_tokens(manager, wallet_address, 50, 'TEST',
                                      'TEST', False, False)
    token_creation_tx.weight = daa.minimum_tx_weight(token_creation_tx)
    token_creation_tx.update_hash()

    assert manager.propagate_tx(token_creation_tx, fails_silently=False)

    add_new_blocks(manager2, 2)

    simulator.run(60)

    connection = FakeConnection(manager, manager2)
    simulator.add_connection(connection)

    simulator.run(60)

    manager.wallet.update_balance()

    print(settings.HATHOR_TOKEN_UID)
    print("HTR balance per address", manager.wallet.get_balance_per_address(settings.HATHOR_TOKEN_UID))
    print("HTR balance per address", manager2.wallet.get_balance_per_address(settings.HATHOR_TOKEN_UID))
