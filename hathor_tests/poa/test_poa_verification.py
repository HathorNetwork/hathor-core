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

from cryptography.hazmat.primitives.asymmetric import ec

from hathor.consensus.consensus_settings import ConsensusType, PoaSettings, PoaSignerSettings
from hathor.consensus.poa import PoaSigner
from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.transaction.poa import PoaBlock
from hathor.transaction.validation_state import ValidationState
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.poa_block_verifier import PoaBlockVerifier
from hathor.verification.vertex_verifier import VertexVerifier
from hathor_tests import unittest


class PoaVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.signer = PoaSigner(ec.generate_private_key(ec.SECP256K1()))
        public_key = self.signer.get_public_key()
        public_key_bytes = get_public_key_bytes_compressed(public_key)

        settings = self._settings._replace(
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            CONSENSUS_ALGORITHM=PoaSettings(
                type=ConsensusType.PROOF_OF_AUTHORITY,
                signers=(PoaSignerSettings(public_key=public_key_bytes),),
            ),
        )

        builder = self.get_builder().set_settings(settings)
        self.manager = self.create_peer_from_builder(builder)
        self.verifiers = self.manager.verification_service.verifiers

    def _get_valid_poa_block(self) -> PoaBlock:
        block = PoaBlock(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=2,
            outputs=[],
            parents=[
                self._settings.GENESIS_BLOCK_HASH,
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH
            ],
        )
        self.signer.sign_block(block)
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        return block

    def test_poa_block_verify_basic(self) -> None:
        block = self._get_valid_poa_block()

        verify_version_basic_wrapped = Mock(wraps=self.verifiers.vertex.verify_version_basic)

        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)
        verify_poa_wrapped = Mock(wraps=self.verifiers.poa_block.verify_poa)

        with (
            patch.object(VertexVerifier, 'verify_version_basic', verify_version_basic_wrapped),
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
            patch.object(PoaBlockVerifier, 'verify_poa', verify_poa_wrapped),
        ):
            self.manager.verification_service.verify_basic(block, self.get_verification_params(self.manager))

        # Vertex methods
        verify_version_basic_wrapped.assert_called_once()

        # Block methods
        verify_weight_wrapped.assert_not_called()
        verify_reward_wrapped.assert_called_once()
        verify_poa_wrapped.assert_called_once()

    def test_poa_block_verify_without_storage(self) -> None:
        block = self._get_valid_poa_block()

        verify_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_outputs)

        verify_pow_wrapped = Mock(wraps=self.verifiers.vertex.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_output_token_indexes_wrapped = Mock(wraps=self.verifiers.block.verify_output_token_indexes)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.vertex.verify_sigops_output)

        with (
            patch.object(VertexVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(VertexVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_output_token_indexes', verify_output_token_indexes_wrapped),
            patch.object(VertexVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(VertexVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
        ):
            self.manager.verification_service.verify_without_storage(block, self.get_verification_params(self.manager))

        # Vertex methods
        verify_outputs_wrapped.assert_called_once()

        # Block methods
        verify_pow_wrapped.assert_not_called()
        verify_no_inputs_wrapped.assert_called_once()
        verify_output_token_indexes_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()

    def test_poa_block_verify(self) -> None:
        block = self._get_valid_poa_block()

        verify_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_outputs)
        verify_headers_wrapped = Mock(wraps=self.verifiers.vertex.verify_headers)

        verify_pow_wrapped = Mock(wraps=self.verifiers.vertex.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_output_token_indexes_wrapped = Mock(wraps=self.verifiers.block.verify_output_token_indexes)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.vertex.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.vertex.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.block.verify_height)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.block.verify_mandatory_signaling)

        with (
            patch.object(VertexVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(VertexVerifier, 'verify_headers', verify_headers_wrapped),
            patch.object(VertexVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_output_token_indexes', verify_output_token_indexes_wrapped),
            patch.object(VertexVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(VertexVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(VertexVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(BlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(BlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
        ):
            self.manager.verification_service.verify(block, self.get_verification_params(self.manager))

        # Vertex methods
        verify_outputs_wrapped.assert_called_once()
        verify_headers_wrapped.assert_called_once()

        # Block methods
        verify_pow_wrapped.assert_not_called()
        verify_no_inputs_wrapped.assert_called_once()
        verify_output_token_indexes_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()

    def test_poa_block_validate_basic(self) -> None:
        block = self._get_valid_poa_block()

        verify_version_basic_wrapped = Mock(wraps=self.verifiers.vertex.verify_version_basic)

        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)
        verify_poa_wrapped = Mock(wraps=self.verifiers.poa_block.verify_poa)

        with (
            patch.object(VertexVerifier, 'verify_version_basic', verify_version_basic_wrapped),
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
            patch.object(PoaBlockVerifier, 'verify_poa', verify_poa_wrapped),
        ):
            self.manager.verification_service.validate_basic(block, self.get_verification_params(self.manager))

        # Vertex methods
        verify_version_basic_wrapped.assert_called_once()

        # Block methods
        verify_weight_wrapped.assert_not_called()
        verify_reward_wrapped.assert_called_once()
        verify_poa_wrapped.assert_called_once()

        # validation should be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.BASIC)

        # full validation should still pass and the validation updated to FULL
        self.manager.verification_service.validate_full(block, self.get_verification_params(self.manager))
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

        # and if running basic validation again it shouldn't validate or change the validation state
        verify_weight_wrapped2 = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped2 = Mock(wraps=self.verifiers.block.verify_reward)

        with (
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped2),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped2),
        ):
            self.manager.verification_service.validate_basic(block, self.get_verification_params(self.manager))

        # Block methods
        verify_weight_wrapped2.assert_not_called()
        verify_reward_wrapped2.assert_not_called()

        # validation should still be FULL, it must not be BASIC
        self.assertEqual(block.get_metadata().validation, ValidationState.FULL)

    def test_poa_block_validate_full(self) -> None:
        block = self._get_valid_poa_block()

        verify_version_basic_wrapped = Mock(wraps=self.verifiers.vertex.verify_version_basic)
        verify_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_outputs)
        verify_headers_wrapped = Mock(wraps=self.verifiers.vertex.verify_headers)

        verify_pow_wrapped = Mock(wraps=self.verifiers.vertex.verify_pow)
        verify_no_inputs_wrapped = Mock(wraps=self.verifiers.block.verify_no_inputs)
        verify_output_token_indexes_wrapped = Mock(wraps=self.verifiers.block.verify_output_token_indexes)
        verify_number_of_outputs_wrapped = Mock(wraps=self.verifiers.vertex.verify_number_of_outputs)
        verify_data_wrapped = Mock(wraps=self.verifiers.block.verify_data)
        verify_sigops_output_wrapped = Mock(wraps=self.verifiers.vertex.verify_sigops_output)
        verify_parents_wrapped = Mock(wraps=self.verifiers.vertex.verify_parents)
        verify_height_wrapped = Mock(wraps=self.verifiers.block.verify_height)
        verify_weight_wrapped = Mock(wraps=self.verifiers.block.verify_weight)
        verify_reward_wrapped = Mock(wraps=self.verifiers.block.verify_reward)
        verify_mandatory_signaling_wrapped = Mock(wraps=self.verifiers.block.verify_mandatory_signaling)
        verify_poa_wrapped = Mock(wraps=self.verifiers.poa_block.verify_poa)

        with (
            patch.object(VertexVerifier, 'verify_version_basic', verify_version_basic_wrapped),
            patch.object(VertexVerifier, 'verify_outputs', verify_outputs_wrapped),
            patch.object(VertexVerifier, 'verify_headers', verify_headers_wrapped),
            patch.object(VertexVerifier, 'verify_pow', verify_pow_wrapped),
            patch.object(BlockVerifier, 'verify_no_inputs', verify_no_inputs_wrapped),
            patch.object(BlockVerifier, 'verify_output_token_indexes', verify_output_token_indexes_wrapped),
            patch.object(VertexVerifier, 'verify_number_of_outputs', verify_number_of_outputs_wrapped),
            patch.object(BlockVerifier, 'verify_data', verify_data_wrapped),
            patch.object(VertexVerifier, 'verify_sigops_output', verify_sigops_output_wrapped),
            patch.object(VertexVerifier, 'verify_parents', verify_parents_wrapped),
            patch.object(BlockVerifier, 'verify_height', verify_height_wrapped),
            patch.object(BlockVerifier, 'verify_weight', verify_weight_wrapped),
            patch.object(BlockVerifier, 'verify_reward', verify_reward_wrapped),
            patch.object(BlockVerifier, 'verify_mandatory_signaling', verify_mandatory_signaling_wrapped),
            patch.object(PoaBlockVerifier, 'verify_poa', verify_poa_wrapped),
        ):
            self.manager.verification_service.validate_full(block, self.get_verification_params(self.manager))

        # Vertex methods
        verify_version_basic_wrapped.assert_called_once()
        verify_outputs_wrapped.assert_called_once()
        verify_headers_wrapped.assert_called_once()

        # Block methods
        verify_pow_wrapped.assert_not_called()
        verify_no_inputs_wrapped.assert_called_once()
        verify_output_token_indexes_wrapped.assert_called_once()
        verify_number_of_outputs_wrapped.assert_called_once()
        verify_data_wrapped.assert_called_once()
        verify_sigops_output_wrapped.assert_called_once()
        verify_parents_wrapped.assert_called_once()
        verify_height_wrapped.assert_called_once()
        verify_weight_wrapped.assert_not_called()
        verify_reward_wrapped.assert_called_once()
        verify_mandatory_signaling_wrapped.assert_called_once()
        verify_poa_wrapped.assert_called_once()
