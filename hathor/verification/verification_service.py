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

from typing import NamedTuple

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.merge_mined_block_verifier import MergeMinedBlockVerifier
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier

cpu = get_cpu_profiler()


class VertexVerifiers(NamedTuple):
    """A group of verifier instances, one for each vertex type."""
    block: BlockVerifier
    merge_mined_block: MergeMinedBlockVerifier
    tx: TransactionVerifier
    token_creation_tx: TokenCreationTransactionVerifier

    @classmethod
    def create_defaults(
        cls,
        *,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService | None = None,
    ) -> 'VertexVerifiers':
        """
        Create a VertexVerifiers instance using the default verifier for each vertex type,
        from all required dependencies.
        """
        return VertexVerifiers(
            block=BlockVerifier(settings=settings, daa=daa, feature_service=feature_service),
            merge_mined_block=MergeMinedBlockVerifier(),
            tx=TransactionVerifier(settings=settings, daa=daa),
            token_creation_tx=TokenCreationTransactionVerifier(settings=settings, daa=daa),
        )


class VerificationService:
    __slots__ = ('verifiers', )

    def __init__(self, *, verifiers: VertexVerifiers) -> None:
        self.verifiers = verifiers

    def validate_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> bool:
        """ Run basic validations (all that are possible without dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `BASIC` and return `True`.
        """
        # XXX: skip validation if previously validated
        if vertex.get_metadata().validation.is_at_least_basic():
            return True

        self.verify_basic(vertex, skip_block_weight_verification=skip_block_weight_verification)
        vertex.set_validation(ValidationState.BASIC)

        return True

    def validate_full(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool = False,
        sync_checkpoints: bool = False,
        reject_locked_reward: bool = True
    ) -> bool:
        """ Run full validations (these need access to all dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `FULL` or `CHECKPOINT_FULL` and return `True`.
        """
        from hathor.transaction.transaction_metadata import ValidationState

        meta = vertex.get_metadata()

        # skip full validation when it is a checkpoint
        if meta.validation.is_checkpoint():
            vertex.set_validation(ValidationState.CHECKPOINT_FULL)
            return True

        # XXX: in some cases it might be possible that this transaction is verified by a checkpoint but we went
        #      directly into trying a full validation so we should check it here to make sure the validation states
        #      ends up being CHECKPOINT_FULL instead of FULL
        if not meta.validation.is_at_least_basic():
            # run basic validation if we haven't already
            self.verify_basic(vertex, skip_block_weight_verification=skip_block_weight_verification)

        self.verify(vertex, reject_locked_reward=reject_locked_reward)
        validation = ValidationState.CHECKPOINT_FULL if sync_checkpoints else ValidationState.FULL
        vertex.set_validation(validation)
        return True

    def verify_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_basic_block(vertex, skip_weight_verification=skip_block_weight_verification)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_basic_merge_mined_block(vertex, skip_weight_verification=skip_block_weight_verification)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self.verifiers.tx.verify_basic(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self.verifiers.token_creation_tx.verify_basic(vertex)
            case _:
                assert_never(vertex.version)

    def _verify_basic_block(self, block: Block, *, skip_weight_verification: bool) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_weight_verification:
            self.verifiers.block.verify_weight(block)
        self.verifiers.block.verify_reward(block)

    def _verify_basic_merge_mined_block(self, block: MergeMinedBlock, *, skip_weight_verification: bool) -> None:
        self._verify_basic_block(block, skip_weight_verification=skip_weight_verification)

    def verify(self, vertex: BaseTransaction, *, reject_locked_reward: bool = True) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_block(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_merge_mined_block(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self.verifiers.tx.verify(vertex, reject_locked_reward=reject_locked_reward)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self.verifiers.token_creation_tx.verify(vertex, reject_locked_reward=reject_locked_reward)
            case _:
                assert_never(vertex.version)

    @cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
    def _verify_block(self, block: Block) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
            (6) whether this block must signal feature support
        """
        # TODO Should we validate a limit of outputs?
        if block.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage(block)

        # (1) and (4)
        self.verifiers.block.verify_parents(block)

        self.verifiers.block.verify_height(block)

        self.verifiers.block.verify_mandatory_signaling(block)

    def _verify_merge_mined_block(self, block: MergeMinedBlock) -> None:
        self._verify_block(block)

    def verify_without_storage(self, vertex: BaseTransaction) -> None:
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_without_storage_block(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_without_storage_merge_mined_block(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self.verifiers.tx.verify_without_storage(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self.verifiers.token_creation_tx.verify_without_storage(vertex)
            case _:
                assert_never(vertex.version)

    def _verify_without_storage_block(self, block: Block) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verifiers.block.verify_pow(block)
        self.verifiers.block.verify_no_inputs(block)
        self.verifiers.block.verify_outputs(block)
        self.verifiers.block.verify_data(block)
        self.verifiers.block.verify_sigops_output(block)

    def _verify_without_storage_merge_mined_block(self, block: MergeMinedBlock) -> None:
        self.verifiers.merge_mined_block.verify_aux_pow(block)
        self._verify_without_storage_block(block)
