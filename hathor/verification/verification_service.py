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

from hathor.conf.settings import HathorSettings
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.exceptions import TxValidationError
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.merge_mined_block_verifier import MergeMinedBlockVerifier
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier


class VertexVerifiers(NamedTuple):
    block: BlockVerifier
    merge_mined_block: MergeMinedBlockVerifier
    tx: TransactionVerifier
    token_creation_tx: TokenCreationTransactionVerifier

    @classmethod
    def create(cls, *, settings: HathorSettings) -> 'VertexVerifiers':
        return VertexVerifiers(
            block=BlockVerifier(settings=settings),
            merge_mined_block=MergeMinedBlockVerifier(settings=settings),
            tx=TransactionVerifier(settings=settings),
            token_creation_tx=TokenCreationTransactionVerifier(settings=settings),
        )


class VerificationService:
    __slots__ = ('verifiers', )

    def __init__(self, *, verifiers: VertexVerifiers) -> None:
        self.verifiers = verifiers

    def validate_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> bool:
        """ Run basic validations (all that are possible without dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `BASIC` and return `True`.
        """
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
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert isinstance(vertex, Block)
                self.verifiers.block.verify_basic(
                    vertex,
                    skip_block_weight_verification=skip_block_weight_verification
                )
            case TxVersion.MERGE_MINED_BLOCK:
                assert isinstance(vertex, MergeMinedBlock)
                self.verifiers.merge_mined_block.verify_basic(
                    vertex,
                    skip_block_weight_verification=skip_block_weight_verification
                )
            case TxVersion.REGULAR_TRANSACTION:
                assert isinstance(vertex, Transaction)
                self.verifiers.tx.verify_basic(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert isinstance(vertex, TokenCreationTransaction)
                self.verifiers.token_creation_tx.verify_basic(vertex)
            case _:
                raise NotImplementedError

    def verify(self, vertex: BaseTransaction, *, reject_locked_reward: bool = True) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert isinstance(vertex, Block)
                self.verifiers.block.verify(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert isinstance(vertex, MergeMinedBlock)
                self.verifiers.merge_mined_block.verify(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert isinstance(vertex, Transaction)
                self.verifiers.tx.verify(vertex, reject_locked_reward=reject_locked_reward)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert isinstance(vertex, TokenCreationTransaction)
                self.verifiers.token_creation_tx.verify(vertex, reject_locked_reward=reject_locked_reward)
            case _:
                raise NotImplementedError

    def verify_without_storage(self, vertex: BaseTransaction) -> None:
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert isinstance(vertex, Block)
                self.verifiers.block.verify_without_storage(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert isinstance(vertex, MergeMinedBlock)
                self.verifiers.merge_mined_block.verify_without_storage(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert isinstance(vertex, Transaction)
                self.verifiers.tx.verify_without_storage(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert isinstance(vertex, TokenCreationTransaction)
                self.verifiers.token_creation_tx.verify_without_storage(vertex)
            case _:
                raise NotImplementedError

    def validate_vertex_error(self, vertex: BaseTransaction) -> tuple[bool, str]:
        """ Verify if tx is valid and return success and possible error message

            :return: Success if tx is valid and possible error message, if not
            :rtype: tuple[bool, str]
        """
        success = True
        message = ''
        try:
            self.verify(vertex)
        except TxValidationError as e:
            success = False
            message = str(e)
        return success, message
