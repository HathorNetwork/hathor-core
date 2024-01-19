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

from typing import cast
from unittest.mock import patch

import pytest

from hathor.crypto.util import decode_address
from hathor.exception import InvalidNewTransaction
from hathor.manager import HathorManager
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch, InvalidInputData, InvalidScriptError, MissingSighashAll
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.scripts.sighash import InputsOutputsLimit, SighashBitmask
from hathor.util import not_none
from tests import unittest
from tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key


class BaseSighashBitmaskTest(unittest.TestCase):
    __test__ = False

    def setUp(self) -> None:
        super().setUp()
        self.manager1: HathorManager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)
        self.manager2: HathorManager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)

        # 1 is Alice
        assert self.manager1.wallet
        self.address1_b58 = self.manager1.wallet.get_unused_address()
        self.private_key1 = self.manager1.wallet.get_private_key(self.address1_b58)
        self.address1 = decode_address(self.address1_b58)

        # 2 is Bob
        assert self.manager2.wallet
        self.address2_b58 = self.manager2.wallet.get_unused_address()
        self.address2 = decode_address(self.address2_b58)

        self.genesis_private_key = get_genesis_key()
        self.genesis_block = self.manager1.tx_storage.get_transaction(self._settings.GENESIS_BLOCK_HASH)

        # Add some blocks so we can spend the genesis outputs
        add_blocks_unlock_reward(self.manager1)

    @patch('hathor.transaction.scripts.opcode.is_opcode_valid', lambda _: True)
    def test_sighash_bitmask(self) -> None:
        # Create a new test token
        token_creation_tx = create_tokens(self.manager1, self.address1_b58)
        token_uid = token_creation_tx.tokens[0]
        token_creation_utxo = token_creation_tx.outputs[0]
        genesis_utxo = self.genesis_block.outputs[0]
        parents = self.manager1.get_new_tx_parents()

        # Alice creates an input spending all created test tokens
        tokens_input = TxInput(not_none(token_creation_tx.hash), 0, b'')

        # Alice creates an output sending half genesis HTR to herself
        alice_output_script = P2PKH.create_output_script(self.address1)
        htr_output = TxOutput(int(genesis_utxo.value / 2), alice_output_script)

        # Alice creates an atomic swap tx that's missing Bob's input, with half genesis HTR, and his output
        atomic_swap_tx = Transaction(
            weight=1,
            inputs=[tokens_input],
            outputs=[htr_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager1.tx_storage,
            timestamp=token_creation_tx.timestamp + 1
        )
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx)

        # Alice signs her input using sighash bitmasks, instead of sighash_all.
        sighash_bitmask = SighashBitmask(inputs=0b1, outputs=0b1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_bitmask)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_bitmask,
        )

        # At this point, the tx is partial. The inputs are valid, but they're mismatched with outputs, and they're
        # missing a SighashAll
        self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx, skip_script=True)

        with pytest.raises(InputOutputMismatch):
            self.manager1.verification_service.verifiers.tx.verify_sum(atomic_swap_tx)

        with pytest.raises(MissingSighashAll):
            self.manager1.verification_service.verify(atomic_swap_tx)

        # Alice sends the tx bytes to Bob, represented here by cloning the tx
        atomic_swap_tx_clone = cast(Transaction, atomic_swap_tx.clone())
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx_clone)

        # Bob creates an input spending all genesis HTR and adds it to the atomic swap tx
        htr_input = TxInput(not_none(self.genesis_block.hash), 0, b'')
        atomic_swap_tx_clone.inputs.append(htr_input)

        # Bob adds an output to receive all test tokens
        bob_output_script = P2PKH.create_output_script(self.address2)
        tokens_output = TxOutput(token_creation_utxo.value, bob_output_script, 1)
        atomic_swap_tx_clone.outputs.append(tokens_output)

        # Bob adds a change output for his HTR
        htr_output = TxOutput(int(genesis_utxo.value / 2), bob_output_script)
        atomic_swap_tx_clone.outputs.append(htr_output)

        # Bob signs his input using sighash_all to complete the tx
        data_to_sign2 = atomic_swap_tx_clone.get_sighash_all()
        assert self.manager2.wallet
        public_bytes2, signature2 = self.manager2.wallet.get_input_aux_data(data_to_sign2, self.genesis_private_key)
        htr_input.data = P2PKH.create_input_data(public_bytes2, signature2)

        # The atomic swap tx is now completed and valid, and can be propagated
        self.manager1.verification_service.verify(atomic_swap_tx_clone)
        self.manager1.propagate_tx(atomic_swap_tx_clone, fails_silently=False)

    @patch('hathor.transaction.scripts.opcode.is_opcode_valid', lambda _: True)
    def test_sighash_bitmask_with_limit(self) -> None:
        # Create a new test token
        token_creation_tx = create_tokens(self.manager1, self.address1_b58)
        token_uid = token_creation_tx.tokens[0]
        token_creation_utxo = token_creation_tx.outputs[0]
        genesis_utxo = self.genesis_block.outputs[0]
        parents = self.manager1.get_new_tx_parents()

        # Alice creates an input spending all created test tokens
        tokens_input = TxInput(not_none(token_creation_tx.hash), 0, b'')

        # Alice creates an output sending half genesis HTR to herself
        alice_output_script = P2PKH.create_output_script(self.address1)
        htr_output = TxOutput(int(genesis_utxo.value / 2), alice_output_script)

        # Alice creates an atomic swap tx that's missing Bob's input, with half genesis HTR, and his output
        atomic_swap_tx = Transaction(
            weight=1,
            inputs=[tokens_input],
            outputs=[htr_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager1.tx_storage,
            timestamp=token_creation_tx.timestamp + 1
        )
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx)

        # Alice signs her input using sighash bitmasks, instead of sighash_all.
        # She also sets max inputs and max outputs limits, including one output for change.
        sighash_bitmask = SighashBitmask(inputs=0b1, outputs=0b1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_bitmask)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_bitmask,
            inputs_outputs_limit=InputsOutputsLimit(max_inputs=2, max_outputs=3)
        )

        # At this point, the tx is partial. The inputs are valid, but they're mismatched with outputs, and they're
        # missing a SighashAll
        self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx, skip_script=True)

        with pytest.raises(InputOutputMismatch):
            self.manager1.verification_service.verifiers.tx.verify_sum(atomic_swap_tx)

        with pytest.raises(MissingSighashAll):
            self.manager1.verification_service.verify(atomic_swap_tx)

        # Alice sends the tx bytes to Bob, represented here by cloning the tx
        atomic_swap_tx_clone = cast(Transaction, atomic_swap_tx.clone())
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx_clone)

        # Bob creates an input spending all genesis HTR and adds it to the atomic swap tx
        htr_input = TxInput(not_none(self.genesis_block.hash), 0, b'')
        atomic_swap_tx_clone.inputs.append(htr_input)

        # Bob adds an output to receive all test tokens
        bob_output_script = P2PKH.create_output_script(self.address2)
        tokens_output = TxOutput(token_creation_utxo.value, bob_output_script, 1)
        atomic_swap_tx_clone.outputs.append(tokens_output)

        # Bob adds two change outputs for his HTR, which violates the maximum tx outputs set by Alice
        htr_output1 = TxOutput(int(genesis_utxo.value / 4), bob_output_script)
        htr_output2 = TxOutput(int(genesis_utxo.value / 4), bob_output_script)
        atomic_swap_tx_clone.outputs.append(htr_output1)
        atomic_swap_tx_clone.outputs.append(htr_output2)

        # Bob signs his input using sighash_all to complete the tx
        data_to_sign2 = atomic_swap_tx_clone.get_sighash_all()
        assert self.manager2.wallet
        public_bytes2, signature2 = self.manager2.wallet.get_input_aux_data(data_to_sign2, self.genesis_private_key)
        htr_input.data = P2PKH.create_input_data(public_bytes2, signature2)

        # The atomic swap tx is not valid and cannot be propagated
        with pytest.raises(InvalidInputData) as e:
            self.manager1.verification_service.verify(atomic_swap_tx_clone)

        self.assertEqual(str(e.value), "Maximum number of outputs exceeded (4 > 3).")

        with pytest.raises(InvalidNewTransaction):
            self.manager1.propagate_tx(atomic_swap_tx_clone, fails_silently=False)

    @patch('hathor.transaction.scripts.opcode.is_opcode_valid', lambda _: True)
    def test_sighash_bitmask_input_not_selected(self) -> None:
        # Create a new test token
        token_creation_tx = create_tokens(self.manager1, self.address1_b58)
        token_uid = token_creation_tx.tokens[0]
        parents = self.manager1.get_new_tx_parents()

        # Alice creates an input spending all created test tokens
        tokens_input = TxInput(not_none(token_creation_tx.hash), 0, b'')

        # Alice creates an input spending all genesis HTR
        genesis_input = TxInput(not_none(self.genesis_block.hash), 0, b'')

        # Alice creates an atomic swap tx
        atomic_swap_tx = Transaction(
            weight=1,
            inputs=[tokens_input, genesis_input],
            outputs=[],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager1.tx_storage,
            timestamp=token_creation_tx.timestamp + 1
        )
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx)

        # Alice signs her token input using sighash bitmasks, instead of sighash_all.
        sighash_bitmask = SighashBitmask(inputs=0b01, outputs=0b00)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_bitmask)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_bitmask,
        )

        # Alice signs her genesis input using the same sighash, so the genesis input is not selected in the bitmask.
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.genesis_private_key)
        genesis_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_bitmask,
        )

        # The inputs are invalid, since one of them doesn't select itself.
        with pytest.raises(InvalidInputData) as e:
            self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)

        self.assertEqual(str(e.value), 'Input at index 1 must select itself when using a custom sighash.')

        with pytest.raises(InvalidInputData) as e:
            self.manager1.verification_service.verify(atomic_swap_tx)

        self.assertEqual(str(e.value), 'Input at index 1 must select itself when using a custom sighash.')

    @patch('hathor.transaction.scripts.opcode.is_opcode_valid', lambda _: True)
    def test_sighash_bitmask_nonexistent_input(self) -> None:
        # Create a new test token
        token_creation_tx = create_tokens(self.manager1, self.address1_b58)
        token_uid = token_creation_tx.tokens[0]
        genesis_utxo = self.genesis_block.outputs[0]
        parents = self.manager1.get_new_tx_parents()

        # Alice creates an input spending all created test tokens
        tokens_input = TxInput(not_none(token_creation_tx.hash), 0, b'')

        # Alice creates an output sending half genesis HTR to herself
        alice_output_script = P2PKH.create_output_script(self.address1)
        htr_output = TxOutput(int(genesis_utxo.value / 2), alice_output_script)

        # Alice creates an atomic swap tx that's missing Bob's input, with half genesis HTR, and his output
        atomic_swap_tx = Transaction(
            weight=1,
            inputs=[tokens_input],
            outputs=[htr_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager1.tx_storage,
            timestamp=token_creation_tx.timestamp + 1
        )
        self.manager1.cpu_mining_service.resolve(atomic_swap_tx)

        # Alice signs her input using sighash bitmasks, instead of sighash_all.
        sighash_bitmask = SighashBitmask(inputs=0b1, outputs=0b1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_bitmask)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=SighashBitmask(inputs=0b11, outputs=0b1),
        )

        # The input is invalid, since it selects a nonexistent input
        with pytest.raises(InvalidScriptError) as e:
            self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)

        assert str(e.value) == 'Custom sighash selected nonexistent input/output.'

        with pytest.raises(InvalidScriptError):
            self.manager1.verification_service.verify(atomic_swap_tx)


class SyncV1SighashTest(unittest.SyncV1Params, BaseSighashBitmaskTest):
    __test__ = True


class SyncV2SighashTest(unittest.SyncV2Params, BaseSighashBitmaskTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSighashTest(unittest.SyncBridgeParams, SyncV2SighashTest):
    pass
