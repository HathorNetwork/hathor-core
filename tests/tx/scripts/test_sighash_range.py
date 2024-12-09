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
from hathor.transaction.exceptions import InputOutputMismatch, InvalidInputData, InvalidScriptError
from hathor.transaction.scripts import MultiSig
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.scripts.sighash import InputsOutputsLimit, SighashRange
from hathor.util import not_none
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script, generate_signature_for_data
from tests import unittest
from tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key


class BaseSighashRangeTest(unittest.TestCase):
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
    def test_sighash_range(self) -> None:
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

        # Alice signs her input using sighash range, instead of sighash_all.
        sighash_range = SighashRange(input_start=0, input_end=1, output_start=0, output_end=1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_range)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_range,
        )

        # At this point, the tx is partial. The inputs are valid, but they're mismatched with outputs
        self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)
        with pytest.raises(InputOutputMismatch):
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
    def test_sighash_range_with_multisig(self) -> None:
        # Create a new test token
        token_creation_tx = create_tokens(self.manager1, self.address1_b58)
        token_uid = token_creation_tx.tokens[0]
        token_creation_utxo = token_creation_tx.outputs[0]
        genesis_utxo = self.genesis_block.outputs[0]
        parents = self.manager1.get_new_tx_parents()

        public_keys = [
            bytes.fromhex('0250bf5890c9c6e9b4ab7f70375d31b827d45d0b7b4e3ba1918bcbe71b412c11d7'),
            bytes.fromhex('02d83dd1e9e0ac7976704eedab43fe0b79309166a47d70ec3ce8bbb08b8414db46'),
            bytes.fromhex('02358c539fa7474bf12f774749d0e1b5a9bc6e50920464818ebdb0043b143ae2ba'),
        ]

        private_keys = [
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e04089abeae5e8a8f75d302020800301d060960864801650304012a0410abbde27221fd302280c13fca7887c85e048190c41403f39b1e9bbc5b6b7c3be4729c054fae9506dc0f8361adcff0ea393f0bb3ca9f992fc2eea83d532691bc9a570ed7fb9e939e6d1787881af40b19fb467f06595229e29b5a6268d831f0287530c7935d154deac61dd4ced988166f9c98054912935b607e2fb332e11c95b30ea4686eb0bda7dd57ed1eeb25b07cea9669dde5210528a00653159626a5baa61cdee7f4',  # noqa: E501
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e040817ca6c6c47ade0de02020800301d060960864801650304012a041003746599b1d7dde5b875e4d8e2c4c157048190a25ccabb17e603260f8a1407bdca24904b6ae0aa9ae225d87552e5a9aa62d98b35b2c6c78f33cb051f3a3932387b4cea6f49e94f14ee856d0b630d77c1299ad7207b0be727d338cf92a3fffe232aff59764240aff84e079a5f6fb3355048ac15703290a005a9a033fdcb7fcf582a5ddf6fd7b7c1193bd7912cd275a88a8a6823b6c3ed291b4a3f4724875a3ae058054c',  # noqa: E501
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e0408089f48fbf59fa92902020800301d060960864801650304012a041072f553e860b77654fd5fb80e5891e7c90481900fde272b88f9a70e7220b2d5adeda1ed29667527caedc2385be7f9e0d63defdde20557e90726e102f879eaf2233cceca8d4af239d5b2a159467255446f001c99b69e570bb176b95248fc21cb752d463b494c2195411639989086336a530d1f4eae91493faf89368f439991baa947ebeca00be7f5099ed69606dc78a4cc384d41542350a9054c5fa1295305dfc37e5989',  # noqa: E501
        ]

        # Change the created token utxo to a MultiSig requiring 2 signatures
        redeem_script = generate_multisig_redeem_script(signatures_required=2, public_key_bytes=public_keys)
        multisig_address_b58 = generate_multisig_address(redeem_script)
        multisig_address = decode_address(multisig_address_b58)
        multisig_script = MultiSig.create_output_script(multisig_address)

        token_creation_utxo.script = multisig_script

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

        # Alice signs her input using sighash range, instead of sighash_all.
        sighash_range = SighashRange(input_start=0, input_end=1, output_start=0, output_end=1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_range)

        signatures = []
        for private_key_hex in private_keys[:2]:
            signature = generate_signature_for_data(data_to_sign1, bytes.fromhex(private_key_hex), password=b'1234')
            signatures.append(signature)

        tokens_input.data = MultiSig.create_input_data(
            redeem_script=redeem_script,
            signatures=signatures,
            sighash=sighash_range,
        )

        # At this point, the tx is partial. The inputs are valid, but they're mismatched with outputs
        self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)
        with pytest.raises(InputOutputMismatch):
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
    def test_sighash_range_with_limit(self) -> None:
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

        # Alice signs her input using sighash range, instead of sighash_all.
        # She also sets max inputs and max outputs limits, including one output for change.
        sighash_range = SighashRange(input_start=0, input_end=1, output_start=0, output_end=1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_range)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_range,
            inputs_outputs_limit=InputsOutputsLimit(max_inputs=2, max_outputs=3)
        )

        # At this point, the tx is partial. The inputs are valid, but they're mismatched with outputs
        self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)
        with pytest.raises(InputOutputMismatch):
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
    def test_sighash_range_input_not_selected(self) -> None:
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

        # Alice signs her token input using sighash range, instead of sighash_all.
        sighash_range = SighashRange(input_start=0, input_end=1, output_start=0, output_end=0)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_range)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_range,
        )

        # Alice signs her genesis input using the same sighash, so the genesis input is not selected in the range.
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.genesis_private_key)
        genesis_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=sighash_range,
        )

        # The inputs are invalid, since one of them doesn't select itself.
        with pytest.raises(InvalidInputData) as e:
            self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)

        self.assertEqual(str(e.value), 'Input at index 1 must select itself when using a custom sighash.')

        with pytest.raises(InvalidInputData) as e:
            self.manager1.verification_service.verify(atomic_swap_tx)

        self.assertEqual(str(e.value), 'Input at index 1 must select itself when using a custom sighash.')

    @patch('hathor.transaction.scripts.opcode.is_opcode_valid', lambda _: True)
    def test_sighash_range_nonexistent_input(self) -> None:
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

        # Alice signs her input using sighash range, instead of sighash_all.
        sighash_range = SighashRange(input_start=0, input_end=1, output_start=0, output_end=1)
        data_to_sign1 = atomic_swap_tx.get_custom_sighash_data(sighash_range)
        assert self.manager1.wallet
        public_bytes1, signature1 = self.manager1.wallet.get_input_aux_data(data_to_sign1, self.private_key1)
        tokens_input.data = P2PKH.create_input_data(
            public_key_bytes=public_bytes1,
            signature=signature1,
            sighash=SighashRange(input_start=0, input_end=2, output_start=0, output_end=1),
        )

        # The input is invalid, since it selects a nonexistent input
        with pytest.raises(InvalidScriptError) as e:
            self.manager1.verification_service.verifiers.tx.verify_inputs(atomic_swap_tx)

        assert str(e.value) == 'Custom sighash selected nonexistent input/output.'

        with pytest.raises(InvalidScriptError):
            self.manager1.verification_service.verify(atomic_swap_tx)


class SyncV1SighashTest(unittest.SyncV1Params, BaseSighashRangeTest):
    __test__ = True


class SyncV2SighashTest(unittest.SyncV2Params, BaseSighashRangeTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSighashTest(unittest.SyncBridgeParams, SyncV2SighashTest):
    pass
