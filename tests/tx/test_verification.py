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

from unittest.mock import Mock, patch

from hathor.crypto.util import get_address_from_public_key
from hathor.manager import HathorManager
from hathor.transaction import BitcoinAuxPow, Block, MergeMinedBlock, Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.merge_mined_block_verifier import MergeMinedBlockVerifier
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier
from tests import unittest
from tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key


class BaseVerificationTest(unittest.TestCase):
    """
    This module implements simple tests related to vertex verification. It does not test the implementation of
    verification methods, but rather simply asserts that each verification method is called when it is supposed to be
    called. This guarantee is mostly useful during the verification refactors.
    """
    __test__ = False

    def setUp(self) -> None:
        super().setUp()
        self.manager: HathorManager = self.create_peer('network')
        self.verifiers = self.manager.verification_service.verifiers

    def _get_valid_block(self) -> Block:
        return Block(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            outputs=[TxOutput(value=6400, script=b'')],
            parents=[
                self._settings.GENESIS_BLOCK_HASH,
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH
            ]
        )

    def _get_valid_merge_mined_block(self) -> MergeMinedBlock:
        return MergeMinedBlock(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            outputs=[TxOutput(value=6400, script=b'')],
            aux_pow=BitcoinAuxPow.dummy(),
            parents=[
                self._settings.GENESIS_BLOCK_HASH,
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH
            ],
        )

    def _get_valid_tx(self) -> Transaction:
        genesis_private_key = get_genesis_key()
        genesis_public_key = genesis_private_key.public_key()
        genesis_block = self.manager.tx_storage.get_transaction(self._settings.GENESIS_BLOCK_HASH)

        utxo = genesis_block.outputs[0]
        address = get_address_from_public_key(genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(utxo.value, script)
        _input = TxInput(self._settings.GENESIS_BLOCK_HASH, 0, b'')

        tx = Transaction(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            inputs=[_input],
            outputs=[output],
            parents=[
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH,
            ]
        )

        data_to_sign = tx.get_sighash_all()
        assert self.manager.wallet
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        return tx

    def _get_valid_token_creation_tx(self) -> TokenCreationTransaction:
        add_blocks_unlock_reward(self.manager)
        assert self.manager.wallet
        return create_tokens(self.manager, self.manager.wallet.get_unused_address())

    def test_block_verify_basic(self) -> None:
        block = self._get_valid_block()

        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)

        with (
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
        ):
            self.manager.verification_service.verify_basic(block)

        # Block methods
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()

    def test_block_verify_without_storage(self) -> None:
        block = self._get_valid_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.block.verify_sigops_output)

        with (
            patch.object(BlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(BlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.verifiers.block.verify_without_storage(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_block_verify(self) -> None:
        block = self._get_valid_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.block.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.block.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.block.verify_height)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.block.verify_mandatory_signaling)

        with (
            patch.object(BlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(BlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(BlockVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(BlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(BlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
        ):
            self.manager.verification_service.verify(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()

    def test_block_validate_basic(self) -> None:
        block = self._get_valid_block()

        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)

        with (
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
        ):
            self.manager.verification_service.validate_basic(block)

        # Block methods
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()

        # validation should be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.BASIC)

        # full validation should still pass and the validation updated to FULL
        self.manager.verification_service.validate_full(block)
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

        # and if running basic validation again it shouldn't validate or change the validation state
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped2 = Mock(wraps=self.verifiers.block.verify_reward)

        with (
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped2),
        ):
            self.manager.verification_service.validate_basic(block)

        # Block methods
        verify_weight_wrapped2.assert_not_called()
        verify_reward_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

    def test_block_validate_full(self) -> None:
        block = self._get_valid_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.block.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.block.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.block.verify_height)
        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.block.verify_mandatory_signaling)

        with (
            patch.object(BlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(BlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(BlockVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(BlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
            patch.object(BlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
        ):
            self.manager.verification_service.validate_full(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()

    def test_merge_mined_block_verify_basic(self) -> None:
        block = self._get_valid_merge_mined_block()

        verify_weight_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_reward)

        with (
            patch.object(MergeMinedBlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_reward', verify_reward_wrapped),
        ):
            self.manager.verification_service.verify_basic(block)

        # Block methods
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()

    def test_merge_mined_block_verify_without_storage(self) -> None:
        block = self._get_valid_merge_mined_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_sigops_output)

        verify_aux_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_aux_pow)

        with (
            patch.object(MergeMinedBlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_aux_pow', verify_aux_pow_wrapped),
        ):
            self.verifiers.merge_mined_block.verify_without_storage(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

        # MergeMinedBlock methods
        verify_pow_wrapped.assert_called_once()

    def test_merge_mined_block_verify(self) -> None:
        block = self._get_valid_merge_mined_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_height)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_mandatory_signaling)

        verify_aux_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_aux_pow)

        with (
            patch.object(MergeMinedBlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_aux_pow', verify_aux_pow_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
        ):
            self.manager.verification_service.verify(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()

        # MergeMinedBlock methods
        verify_pow_wrapped.assert_called_once()

    def test_merge_mined_block_validate_basic(self) -> None:
        block = self._get_valid_merge_mined_block()

        verify_weight_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_reward)

        with (
            patch.object(MergeMinedBlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_reward', verify_reward_wrapped),
        ):
            self.manager.verification_service.validate_basic(block)

        # Block methods
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()

        # validation should be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.BASIC)

        # full validation should still pass and the validation updated to FULL
        self.manager.verification_service.validate_full(block)
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

        # and if running basic validation again it shouldn't validate or change the validation state
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped2 = Mock(wraps=self.verifiers.block.verify_reward)

        with (
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped2),
        ):
            self.manager.verification_service.validate_basic(block)

        # Block methods
        verify_weight_wrapped2.assert_not_called()
        verify_reward_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

    def test_merge_mined_block_validate_full(self) -> None:
        block = self._get_valid_merge_mined_block()

        verify_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_no_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_height)
        verify_weight_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_reward)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_mandatory_signaling)

        verify_aux_pow_wrapped = Mock(wraps=self.verifiers.merge_mined_block.verify_aux_pow)

        with (
            patch.object(MergeMinedBlockVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_reward', verify_reward_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_aux_pow', verify_aux_pow_wrapped),
            patch.object(MergeMinedBlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
        ):
            self.manager.verification_service.validate_full(block)

        # Block methods
        verify_pow_wrapped.assert_called_once()
        verify_no_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_reward_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()

        # MergeMinedBlock methods
        verify_pow_wrapped.assert_called_once()

    def test_transaction_verify_basic(self) -> None:
        tx = self._get_valid_tx()

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_output)

        with (
            patch.object(TransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.manager.verification_service.verify_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_transaction_verify_without_storage(self) -> None:
        tx = self._get_valid_tx()

        verify_pow_wrapped = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_output)

        with (
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.verifiers.tx.verify_without_storage(tx)

        # Transaction methods
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_transaction_verify(self) -> None:
        add_blocks_unlock_reward(self.manager)
        tx = self._get_valid_tx()

        verify_pow_wrapped = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_output)
        verify_sigops_input_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_input)
        verify_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_inputs)
        verify_script_wrapped = Mock(wraps=self.verifiers.tx.verify_script)
        verify_parents_wrapped = Mock(wraps=self.verifiers.tx.verify_parents)
        verify_sum_wrapped = Mock(wraps=self.verifiers.tx.verify_sum)
        verify_reward_locked_wrapped = Mock(wraps=self.verifiers.tx.verify_reward_locked)

        with (
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_input', verify_sigops_input_wrapped),
            patch.object(TransactionVerifier, 'verify_inputs', verify_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_script', verify_script_wrapped),
            patch.object(TransactionVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(TransactionVerifier, 'verify_sum', verify_sum_wrapped),
            patch.object(TransactionVerifier, 'verify_reward_locked', verify_reward_locked_wrapped),
        ):
            self.manager.verification_service.verify(tx)

        # Transaction methods
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_sigops_input_wrapped.assert_called_once()
        verify_inputs_wrapped.assert_called_once()
        verify_script_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_sum_wrapped.assert_called_once()
        verify_reward_locked_wrapped.assert_called_once()

    def test_transaction_validate_basic(self) -> None:
        # add enough blocks so that it can be fully validated later on the tests
        add_blocks_unlock_reward(self.manager)
        tx = self._get_valid_tx()

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_output)

        with (
            patch.object(TransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.manager.verification_service.validate_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

        # validation should be BASIC
        self.assertEqual(tx.get_metadata().validation, ValidationState.BASIC)

        # full validation should still pass and the validation updated to FULL
        self.manager.verification_service.validate_full(tx)
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

        # and if running basic validation again it shouldn't validate or change the validation state
        verify_parents_basic_wrapped2 = Mock(wraps=self.verifiers.tx.verify_parents_basic)
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.tx.verify_weight)
        verify_pow_wrapped2 = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped2 = Mock(wraps=self.verifiers.tx.verify_sigops_output)

        with (
            patch.object(TransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped2),
            patch.object(TransactionVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped2),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped2),
        ):
            self.manager.verification_service.validate_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped2.assert_not_called()
        verify_weight_wrapped2.assert_not_called()
        verify_pow_wrapped2.assert_not_called()
        verify_number_of_inputs_wrapped2.assert_not_called()
        verify_outputs_wrapped2.assert_not_called()
        verify_number_of_outputs_wrapped2.assert_not_called()
        verify_sigops_output_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

    def test_transaction_validate_full(self) -> None:
        add_blocks_unlock_reward(self.manager)
        tx = self._get_valid_tx()

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_output)
        verify_sigops_input_wrapped = Mock(wraps=self.verifiers.tx.verify_sigops_input)
        verify_inputs_wrapped = Mock(wraps=self.verifiers.tx.verify_inputs)
        verify_script_wrapped = Mock(wraps=self.verifiers.tx.verify_script)
        verify_parents_wrapped = Mock(wraps=self.verifiers.tx.verify_parents)
        verify_sum_wrapped = Mock(wraps=self.verifiers.tx.verify_sum)
        verify_reward_locked_wrapped = Mock(wraps=self.verifiers.tx.verify_reward_locked)

        with (
            patch.object(TransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(TransactionVerifier, 'verify_sigops_input', verify_sigops_input_wrapped),
            patch.object(TransactionVerifier, 'verify_inputs', verify_inputs_wrapped),
            patch.object(TransactionVerifier, 'verify_script', verify_script_wrapped),
            patch.object(TransactionVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(TransactionVerifier, 'verify_sum', verify_sum_wrapped),
            patch.object(TransactionVerifier, 'verify_reward_locked', verify_reward_locked_wrapped),
        ):
            self.manager.verification_service.validate_full(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        assert verify_pow_wrapped.call_count == 2
        assert verify_number_of_inputs_wrapped.call_count == 2
        assert verify_outputs_wrapped.call_count == 2
        assert verify_number_of_outputs_wrapped.call_count == 2
        assert verify_sigops_output_wrapped.call_count == 2
        verify_sigops_input_wrapped.assert_called_once()
        verify_inputs_wrapped.assert_called_once()
        verify_script_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_sum_wrapped.assert_called_once()
        verify_reward_locked_wrapped.assert_called_once()

        # validation should be FULL
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

        # and if running full validation again it shouldn't validate or change the validation state
        verify_parents_basic_wrapped2 = Mock(wraps=self.verifiers.tx.verify_parents_basic)
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.tx.verify_weight)
        verify_pow_wrapped2 = Mock(wraps=self.verifiers.tx.verify_pow)
        verify_number_of_inputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_number_of_inputs)
        verify_outputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_outputs)
        verify_number_of_outputs_wrapped2 = Mock(wraps=self.verifiers.tx.verify_number_of_outputs)
        verify_sigops_output_wrapped2 = Mock(wraps=self.verifiers.tx.verify_sigops_output)

        with (
            patch.object(TransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped2),
            patch.object(TransactionVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(TransactionVerifier, 'verify_pow', verify_pow_wrapped2),
            patch.object(TransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_outputs', verify_outputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped2),
            patch.object(TransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped2),
        ):
            self.manager.verification_service.validate_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped2.assert_not_called()
        verify_weight_wrapped2.assert_not_called()
        verify_pow_wrapped2.assert_not_called()
        verify_number_of_inputs_wrapped2.assert_not_called()
        verify_outputs_wrapped2.assert_not_called()
        verify_number_of_outputs_wrapped2.assert_not_called()
        verify_sigops_output_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

    def test_token_creation_transaction_verify_basic(self) -> None:
        tx = self._get_valid_token_creation_tx()

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.manager.verification_service.verify_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_token_creation_transaction_verify_without_storage(self) -> None:
        tx = self._get_valid_token_creation_tx()

        verify_pow_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.verifiers.token_creation_tx.verify_without_storage(tx)

        # Transaction methods
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_token_creation_transaction_verify(self) -> None:
        tx = self._get_valid_token_creation_tx()

        verify_pow_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)
        verify_sigops_input_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_input)
        verify_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_inputs)
        verify_script_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_script)
        verify_parents_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_parents)
        verify_sum_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sum)
        verify_reward_locked_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_reward_locked)

        verify_token_info_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_token_info)
        verify_minted_tokens_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_minted_tokens)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_input', verify_sigops_input_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_inputs', verify_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_script', verify_script_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sum', verify_sum_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_reward_locked', verify_reward_locked_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_token_info', verify_token_info_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_minted_tokens', verify_minted_tokens_wrapped),
        ):
            self.manager.verification_service.verify(tx)

        # Transaction methods
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_sigops_input_wrapped.assert_called_once()
        verify_inputs_wrapped.assert_called_once()
        verify_script_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_sum_wrapped.assert_called_once()
        verify_reward_locked_wrapped.assert_called_once()

        # TokenCreationTransaction methods
        verify_token_info_wrapped.assert_called_once()
        verify_minted_tokens_wrapped.assert_called_once()

    def test_token_creation_transaction_validate_basic(self) -> None:
        tx = self._get_valid_token_creation_tx()
        tx.get_metadata().validation = ValidationState.INITIAL

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.manager.verification_service.validate_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        verify_pow_wrapped.assert_called_once()
        verify_number_of_inputs_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

        # validation should be BASIC
        self.assertEqual(tx.get_metadata().validation, ValidationState.BASIC)

        # full validation should still pass and the validation updated to FULL
        self.manager.verification_service.validate_full(tx)
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

        # and if running basic validation again it shouldn't validate or change the validation state
        verify_parents_basic_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_parents_basic)
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_weight)
        verify_pow_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped2 = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs',
                         verify_number_of_inputs_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped2),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped2),
        ):
            self.manager.verification_service.validate_basic(tx)

        # Transaction methods
        verify_parents_basic_wrapped2.assert_not_called()
        verify_weight_wrapped2.assert_not_called()
        verify_pow_wrapped2.assert_not_called()
        verify_number_of_inputs_wrapped2.assert_not_called()
        verify_outputs_wrapped2.assert_not_called()
        verify_number_of_outputs_wrapped2.assert_not_called()
        verify_sigops_output_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(tx.get_metadata().validation, ValidationState.FULL)

    def test_token_creation_transaction_validate_full(self) -> None:
        tx = self._get_valid_token_creation_tx()
        tx.get_metadata().validation = ValidationState.INITIAL

        verify_parents_basic_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_parents_basic)
        verify_weight_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_weight)
        verify_pow_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_pow)
        verify_number_of_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_inputs)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_outputs)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_number_of_outputs)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_output)
        verify_sigops_input_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sigops_input)
        verify_inputs_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_inputs)
        verify_script_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_script)
        verify_parents_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_parents)
        verify_sum_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_sum)
        verify_reward_locked_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_reward_locked)

        verify_token_info_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_token_info)
        verify_minted_tokens_wrapped = Mock(wraps=self.verifiers.token_creation_tx.verify_minted_tokens)

        with (
            patch.object(TokenCreationTransactionVerifier, 'verify_parents_basic', verify_parents_basic_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_inputs', verify_number_of_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_number_of_outputs',
                         verify_number_of_outputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sigops_input', verify_sigops_input_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_inputs', verify_inputs_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_script', verify_script_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_sum', verify_sum_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_reward_locked', verify_reward_locked_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_token_info', verify_token_info_wrapped),
            patch.object(TokenCreationTransactionVerifier, 'verify_minted_tokens', verify_minted_tokens_wrapped),
        ):
            self.manager.verification_service.validate_full(tx)

        # Transaction methods
        verify_parents_basic_wrapped.assert_called_once()
        verify_weight_wrapped.assert_called_once()
        assert verify_pow_wrapped.call_count == 2
        assert verify_number_of_inputs_wrapped.call_count == 2
        assert verify_outputs_wrapped.call_count == 2
        assert verify_number_of_outputs_wrapped.call_count == 2
        assert verify_sigops_output_wrapped.call_count == 2
        verify_sigops_input_wrapped.assert_called_once()
        verify_inputs_wrapped.assert_called_once()
        verify_script_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_sum_wrapped.assert_called_once()
        verify_reward_locked_wrapped.assert_called_once()

        # TokenCreationTransaction methods
        verify_token_info_wrapped.assert_called_once()
        verify_minted_tokens_wrapped.assert_called_once()


class SyncV1VerificationTest(unittest.SyncV1Params, BaseVerificationTest):
    __test__ = True


class SyncV2VerificationTest(unittest.SyncV2Params, BaseVerificationTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeVerificationTest(unittest.SyncBridgeParams, SyncV2VerificationTest):
    pass
