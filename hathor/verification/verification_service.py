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

from typing_extensions import assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.multiprocessor import Multiprocessor
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.verification.verification_dependencies import (
    BasicBlockDependencies,
    BlockDependencies,
    TransactionDependencies,
)
from hathor.verification.vertex_verifiers import VertexVerifiers

cpu = get_cpu_profiler()


class VerificationService:
    __slots__ = ('verifiers', '_daa', '_feature_service', '_mp')

    def __init__(
        self,
        *,
        verifiers: VertexVerifiers,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService | None = None
    ) -> None:
        self.verifiers = verifiers
        self._daa = daa
        self._feature_service = feature_service
        self._mp = Multiprocessor()

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

    async def validate_full_async(
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
            await self.verify_basic_async(vertex, skip_block_weight_verification=skip_block_weight_verification)

        await self.verify_async(vertex, reject_locked_reward=reject_locked_reward)
        validation = ValidationState.CHECKPOINT_FULL if sync_checkpoints else ValidationState.FULL
        vertex.set_validation(validation)
        return True

    def verify_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        assert self._feature_service is not None

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                block_deps = BasicBlockDependencies.create(
                    vertex, self._daa, skip_weight_verification=skip_block_weight_verification
                )
                _verify_basic_block(
                    self.verifiers, vertex, block_deps, skip_weight_verification=skip_block_weight_verification
                )
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                block_deps = BasicBlockDependencies.create(
                    vertex, self._daa, skip_weight_verification=skip_block_weight_verification
                )
                _verify_basic_merge_mined_block(
                    self.verifiers, vertex, block_deps, skip_weight_verification=skip_block_weight_verification
                )
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                _verify_basic_tx(self.verifiers, vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                _verify_basic_token_creation_tx(self.verifiers, vertex)
            case _:
                assert_never(vertex.version)

    async def verify_basic_async(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool = False
    ) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        assert self._feature_service is not None

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                block_deps = BasicBlockDependencies.create(
                    vertex, self._daa, skip_weight_verification=skip_block_weight_verification
                )
                self._mp.run(_verify_basic_block,
                    self.verifiers, vertex, block_deps, skip_weight_verification=skip_block_weight_verification
                )
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                block_deps = BasicBlockDependencies.create(
                    vertex, self._daa, skip_weight_verification=skip_block_weight_verification
                )
                self._mp.run(_verify_basic_merge_mined_block,
                    self.verifiers, vertex, block_deps, skip_weight_verification=skip_block_weight_verification
                )
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._mp.run(_verify_basic_tx, self.verifiers, vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._mp.run(_verify_basic_token_creation_tx, self.verifiers, vertex)
            case _:
                assert_never(vertex.version)

    def verify(self, vertex: BaseTransaction, *, reject_locked_reward: bool = True) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        if vertex.is_genesis:
            # TODO do genesis validation
            return

        assert self._feature_service is not None
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                block_deps = BlockDependencies.create(vertex, self._feature_service)
                _verify_block(self.verifiers, vertex, block_deps)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                block_deps = BlockDependencies.create(vertex, self._feature_service)
                _verify_merge_mined_block(self.verifiers, vertex, block_deps)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                tx_deps = TransactionDependencies.create(vertex)
                _verify_tx(self.verifiers, vertex, tx_deps, reject_locked_reward=reject_locked_reward)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                tx_deps = TransactionDependencies.create(vertex)
                _verify_token_creation_tx(self.verifiers, vertex, tx_deps, reject_locked_reward=reject_locked_reward)
            case _:
                assert_never(vertex.version)

    async def verify_async(self, vertex: BaseTransaction, *, reject_locked_reward: bool = True) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        if vertex.is_genesis:
            # TODO do genesis validation
            return

        assert self._feature_service is not None
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                block_deps = BlockDependencies.create(vertex, self._feature_service)
                self._mp.run(_verify_block, self.verifiers, vertex, block_deps)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                block_deps = BlockDependencies.create(vertex, self._feature_service)
                self._mp.run(_verify_merge_mined_block, self.verifiers, vertex, block_deps)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                tx_deps = TransactionDependencies.create(vertex)
                self._mp.run(_verify_tx, self.verifiers, vertex, tx_deps, reject_locked_reward=reject_locked_reward)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                tx_deps = TransactionDependencies.create(vertex)
                self._mp.run(
                    _verify_token_creation_tx,
                    self.verifiers,
                    vertex,
                    tx_deps,
                    reject_locked_reward=reject_locked_reward
                )
            case _:
                assert_never(vertex.version)

    def verify_without_storage(self, vertex: BaseTransaction) -> None:
        _verify_without_storage(self.verifiers, vertex)


def _verify_without_storage(verifiers: VertexVerifiers, vertex: BaseTransaction) -> None:
    # We assert with type() instead of isinstance() because each subclass has a specific branch.
    match vertex.version:
        case TxVersion.REGULAR_BLOCK:
            assert type(vertex) is Block
            _verify_without_storage_block(verifiers, vertex)
        case TxVersion.MERGE_MINED_BLOCK:
            assert type(vertex) is MergeMinedBlock
            _verify_without_storage_merge_mined_block(verifiers, vertex)
        case TxVersion.REGULAR_TRANSACTION:
            assert type(vertex) is Transaction
            _verify_without_storage_tx(verifiers, vertex)
        case TxVersion.TOKEN_CREATION_TRANSACTION:
            assert type(vertex) is TokenCreationTransaction
            _verify_without_storage_token_creation_tx(verifiers, vertex)
        case _:
            assert_never(vertex.version)


def _verify_basic_block(
    verifiers: VertexVerifiers,
    block: Block,
    block_deps: BasicBlockDependencies,
    *,
    skip_weight_verification: bool
) -> None:
    """Partially run validations, the ones that need parents/inputs are skipped."""
    if not skip_weight_verification:
        verifiers.block.verify_weight(block, block_deps)
    verifiers.block.verify_reward(block, block_deps)


def _verify_basic_merge_mined_block(
    verifiers: VertexVerifiers,
    block: MergeMinedBlock,
    block_deps: BasicBlockDependencies,
    *,
    skip_weight_verification: bool
) -> None:
    _verify_basic_block(verifiers, block, block_deps, skip_weight_verification=skip_weight_verification)


def _verify_basic_tx(verifiers: VertexVerifiers, tx: Transaction) -> None:
    """Partially run validations, the ones that need parents/inputs are skipped."""
    if tx.is_genesis:
        # TODO do genesis validation?
        return
    verifiers.tx.verify_parents_basic(tx)
    verifiers.tx.verify_weight(tx)
    _verify_without_storage(verifiers, tx)


def _verify_basic_token_creation_tx(verifiers: VertexVerifiers, tx: TokenCreationTransaction) -> None:
    _verify_basic_tx(verifiers, tx)


@cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
def _verify_block(verifiers: VertexVerifiers, block: Block, block_deps: BlockDependencies) -> None:
    """
        (1) confirms at least two pending transactions and references last block
        (2) solves the pow with the correct weight (done in HathorManager)
        (3) creates the correct amount of tokens in the output (done in HathorManager)
        (4) all parents must exist and have timestamp smaller than ours
        (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
        (6) whether this block must signal feature support
    """
    # TODO Should we validate a limit of outputs?

    _verify_without_storage(verifiers, block)

    # (1) and (4)
    verifiers.vertex.verify_parents(block, block_deps)

    verifiers.block.verify_height(block)

    verifiers.block.verify_mandatory_signaling(block_deps)


def _verify_merge_mined_block(
    verifiers: VertexVerifiers,
    block: MergeMinedBlock,
    block_deps: BlockDependencies
) -> None:
    verifiers.merge_mined_block.verify_aux_pow(block, block_deps)
    _verify_block(block, block_deps)


@cpu.profiler(key=lambda _, tx: 'tx-verify!{}'.format(tx.hash.hex()))
def _verify_tx(
    verifiers: VertexVerifiers,
    tx: Transaction,
    tx_deps: TransactionDependencies,
    *,
    reject_locked_reward: bool,
) -> None:
    """ Common verification for all transactions:
       (i) number of inputs is at most 256
      (ii) number of outputs is at most 256
     (iii) confirms at least two pending transactions
      (iv) solves the pow (we verify weight is correct in HathorManager)
       (v) validates signature of inputs
      (vi) validates public key and output (of the inputs) addresses
     (vii) validate that both parents are valid
    (viii) validate input's timestamps
      (ix) validate inputs and outputs sum
    """
    _verify_without_storage(verifiers, tx)
    verifiers.tx.verify_sigops_input(tx, tx_deps)
    verifiers.tx.verify_inputs(tx, tx_deps)  # need to run verify_inputs first to check if all inputs exist
    verifiers.vertex.verify_parents(tx, tx_deps)
    verifiers.tx.verify_sum(tx_deps)
    if reject_locked_reward:
        verifiers.tx.verify_reward_locked(tx, tx_deps)


def _verify_token_creation_tx(
    verifiers: VertexVerifiers,
    tx: TokenCreationTransaction,
    tx_deps: TransactionDependencies,
    *,
    reject_locked_reward: bool
) -> None:
    """ Run all validations as regular transactions plus validation on token info.

    We also overload verify_sum to make some different checks
    """
    _verify_tx(tx, tx_deps, reject_locked_reward=reject_locked_reward)
    verifiers.token_creation_tx.verify_minted_tokens(tx, tx_deps)
    verifiers.token_creation_tx.verify_token_info(tx)


def _verify_without_storage_block(verifiers: VertexVerifiers, block: Block) -> None:
    """ Run all verifications that do not need a storage.
    """
    verifiers.vertex.verify_pow(block)
    verifiers.block.verify_no_inputs(block)
    verifiers.vertex.verify_outputs(block)
    verifiers.block.verify_output_token_indexes(block)
    verifiers.block.verify_data(block)
    verifiers.vertex.verify_sigops_output(block)


def _verify_without_storage_merge_mined_block(verifiers: VertexVerifiers, block: MergeMinedBlock) -> None:
    _verify_without_storage_block(verifiers, block)


def _verify_without_storage_tx(verifiers: VertexVerifiers, tx: Transaction) -> None:
    """ Run all verifications that do not need a storage.
    """
    verifiers.vertex.verify_pow(tx)
    verifiers.tx.verify_number_of_inputs(tx)
    verifiers.vertex.verify_outputs(tx)
    verifiers.tx.verify_output_token_indexes(tx)
    verifiers.vertex.verify_sigops_output(tx)


def _verify_without_storage_token_creation_tx(verifiers: VertexVerifiers, tx: TokenCreationTransaction) -> None:
    _verify_without_storage_tx(verifiers, tx)
