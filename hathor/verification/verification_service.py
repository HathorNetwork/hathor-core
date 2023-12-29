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
import functools
from collections.abc import Awaitable
from typing import Callable, Literal, overload

from twisted.internet import defer
from typing_extensions import assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.multiprocessor.multiprocessor import Multiprocessor
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction
from hathor.transaction.base_transaction import vertex_from_bytes
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.transaction.vertex import BlockType, MergeMinedBlockType, TokenCreationTransactionType, TransactionType
from hathor.verification.verification_dependencies import BlockDependencies, TransactionDependencies
from hathor.verification.vertex_verifiers import VertexVerifiers

cpu = get_cpu_profiler()


class VerificationService:
    __slots__ = ('verifiers', '_daa', '_feature_service', '_mp')

    def __init__(
        self,
        *,
        verifiers: VertexVerifiers,
        daa: DifficultyAdjustmentAlgorithm,
        multiprocessor: Multiprocessor,
        feature_service: FeatureService | None = None,
    ) -> None:
        self.verifiers = verifiers
        self._daa = daa
        self._mp = multiprocessor
        self._feature_service = feature_service

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

    @overload
    async def validate_full(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool,
        sync_checkpoints: bool,
        reject_locked_reward: bool,
        sync: Literal[False],
    ) -> bool:
        ...

    @overload
    def validate_full(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool = False,
        sync_checkpoints: bool = False,
        reject_locked_reward: bool = True,
        sync: Literal[True] = True,
    ) -> bool:
        ...

    def validate_full(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool = False,
        sync_checkpoints: bool = False,
        reject_locked_reward: bool = True,
        sync: bool = True,
    ) -> Awaitable[bool] | bool:
        """ Run full validations (these need access to all dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `FULL` or `CHECKPOINT_FULL` and return `True`.
        """
        from hathor.transaction.transaction_metadata import ValidationState

        meta = vertex.get_metadata()

        # skip full validation when it is a checkpoint
        if meta.validation.is_checkpoint():
            vertex.set_validation(ValidationState.CHECKPOINT_FULL)
            return True if sync else defer.succeed(True)

        # XXX: in some cases it might be possible that this transaction is verified by a checkpoint but we went
        #      directly into trying a full validation so we should check it here to make sure the validation states
        #      ends up being CHECKPOINT_FULL instead of FULL
        if not meta.validation.is_at_least_basic():
            # run basic validation if we haven't already
            self.verify_basic(vertex, skip_block_weight_verification=skip_block_weight_verification)

        if sync:
            self.verify(vertex, reject_locked_reward=reject_locked_reward, sync=True)
            validation = ValidationState.CHECKPOINT_FULL if sync_checkpoints else ValidationState.FULL
            vertex.set_validation(validation)
            return True
        else:
            x = self.verify(vertex, reject_locked_reward=reject_locked_reward, sync=False)
            y = x.__await__()

    def verify_basic(self, base_tx: BaseTransaction, *, skip_block_weight_verification: bool = False) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        assert self._feature_service is not None
        vertex = base_tx.as_vertex()

        match vertex:
            case BlockType(block):
                deps = BlockDependencies.create(block, self._daa, self._feature_service)
                self._verify_basic_block(
                    block, self.verifiers, deps, skip_weight_verification=skip_block_weight_verification
                )
            case MergeMinedBlockType(block):
                deps = BlockDependencies.create(block, self._daa, self._feature_service)
                self._verify_basic_merge_mined_block(
                    block, self.verifiers, deps, skip_weight_verification=skip_block_weight_verification
                )
            case TransactionType(tx):
                self._verify_basic_tx(tx, self.verifiers)
            case TokenCreationTransactionType(tx):
                self._verify_basic_token_creation_tx(tx, self.verifiers)
            case _:
                assert_never(vertex)

    @classmethod
    def _verify_basic_block(
        cls,
        block: Block,
        verifiers: VertexVerifiers,
        deps: BlockDependencies,
        *,
        skip_weight_verification: bool
    ) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_weight_verification:
            verifiers.block.verify_weight(block, deps)
        verifiers.block.verify_reward(block, deps)

    @classmethod
    def _verify_basic_merge_mined_block(
        cls,
        block: MergeMinedBlock,
        verifiers: VertexVerifiers,
        deps: BlockDependencies,
        *,
        skip_weight_verification: bool
    ) -> None:
        cls._verify_basic_block(block, verifiers, deps, skip_weight_verification=skip_weight_verification)

    @classmethod
    def _verify_basic_tx(cls, tx: Transaction, verifiers: VertexVerifiers) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if tx.is_genesis:
            # TODO do genesis validation?
            return
        verifiers.tx.verify_parents_basic(tx)
        verifiers.tx.verify_weight(tx)
        cls._verify_without_storage(tx, verifiers)

    @classmethod
    def _verify_basic_token_creation_tx(cls, tx: TokenCreationTransaction, verifiers: VertexVerifiers) -> None:
        cls._verify_basic_tx(tx, verifiers)

    @overload
    async def verify(self, base_tx: BaseTransaction, *, reject_locked_reward: bool, sync: Literal[False]) -> None:
        ...

    @overload
    def verify(
        self,
        base_tx: BaseTransaction,
        *,
        reject_locked_reward: bool = True,
        sync: Literal[True] = True
    ) -> None:
        ...

    def verify(
        self,
        base_tx: BaseTransaction,
        *,
        reject_locked_reward: bool = True,
        sync: bool = True,
    ) -> Awaitable[None] | None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""

        if base_tx.is_genesis:
            # TODO do genesis validation
            return None if sync else defer.succeed(None)

        assert self._feature_service is not None
        vertex = base_tx.as_vertex()

        execute_verification: Callable[[], None]

        match vertex:
            case BlockType(block):
                block_deps = BlockDependencies.create(block, self._daa, self._feature_service)
                execute_verification = functools.partial(
                    self._verify_block, block.get_struct(), self.verifiers, block_deps
                )
            case MergeMinedBlockType(block):
                block_deps = BlockDependencies.create(block, self._daa, self._feature_service)
                execute_verification = functools.partial(
                    self._verify_merge_mined_block, block.get_struct(), self.verifiers, block_deps
                )
            case TransactionType(tx):
                tx_deps = TransactionDependencies.create(tx)
                execute_verification = functools.partial(
                    self._verify_tx,
                    tx.get_struct(),
                    self.verifiers,
                    tx_deps,
                    reject_locked_reward=reject_locked_reward
                )
            case TokenCreationTransactionType(tx):
                tx_deps = TransactionDependencies.create(tx)
                execute_verification = functools.partial(
                    self._verify_token_creation_tx,
                    tx.get_struct(),
                    self.verifiers,
                    tx_deps,
                    reject_locked_reward=reject_locked_reward
                )
            case _:
                assert_never(vertex)

        if sync:
            execute_verification()
            return None

        return self._mp.run(execute_verification)

    # @cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
    @classmethod
    def _verify_block(cls, block_bytes: bytes, verifiers: VertexVerifiers, deps: BlockDependencies) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
            (6) whether this block must signal feature support
        """
        # TODO Should we validate a limit of outputs?
        block = vertex_from_bytes(block_bytes, Block)

        cls._verify_without_storage(block, verifiers)

        # (1) and (4)
        verifiers.vertex.verify_parents(block, deps)

        verifiers.block.verify_height(block, deps)

        verifiers.block.verify_mandatory_signaling(deps)

    @classmethod
    def _verify_merge_mined_block(
        cls,
        block_bytes: bytes,
        verifiers: VertexVerifiers,
        deps: BlockDependencies
    ) -> None:
        cls._verify_block(block_bytes, verifiers, deps)

    # @cpu.profiler(key=lambda _, tx: 'tx-verify!{}'.format(tx.hash.hex()))
    @classmethod
    def _verify_tx(
        cls,
        tx_bytes: bytes,
        verifiers: VertexVerifiers,
        deps: TransactionDependencies,
        *,
        reject_locked_reward: bool
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
        tx = vertex_from_bytes(tx_bytes, Transaction)
        cls._verify_without_storage(tx, verifiers)
        verifiers.tx.verify_sigops_input(tx, deps)
        verifiers.tx.verify_inputs(tx, deps)  # need to run verify_inputs first to check if all inputs exist
        verifiers.vertex.verify_parents(tx, deps)
        verifiers.tx.verify_sum(deps)
        if reject_locked_reward:
            verifiers.tx.verify_reward_locked(tx, deps)

    @classmethod
    def _verify_token_creation_tx(
        cls,
        tx_bytes: bytes,
        verifiers: VertexVerifiers,
        deps: TransactionDependencies,
        *,
        reject_locked_reward: bool
    ) -> None:
        """ Run all validations as regular transactions plus validation on token info.

        We also overload verify_sum to make some different checks
        """
        tx = vertex_from_bytes(tx_bytes, TokenCreationTransaction)
        cls._verify_tx(tx_bytes, verifiers, deps, reject_locked_reward=reject_locked_reward)
        verifiers.token_creation_tx.verify_minted_tokens(tx, deps)
        verifiers.token_creation_tx.verify_token_info(tx)

    def verify_without_storage(self, base_tx: BaseTransaction) -> None:
        self._verify_without_storage(base_tx, self.verifiers)

    @classmethod
    def _verify_without_storage(cls, base_tx: BaseTransaction, verifiers: VertexVerifiers) -> None:
        vertex = base_tx.as_vertex()
        match vertex:
            case BlockType(block):
                cls._verify_without_storage_block(block, verifiers)
            case MergeMinedBlockType(block):
                cls._verify_without_storage_merge_mined_block(block, verifiers)
            case TransactionType(tx):
                cls._verify_without_storage_tx(tx, verifiers)
            case TokenCreationTransactionType(tx):
                cls._verify_without_storage_token_creation_tx(tx, verifiers)
            case _:
                assert_never(vertex)

    @classmethod
    def _verify_without_storage_block(cls, block: Block, verifiers: VertexVerifiers) -> None:
        """ Run all verifications that do not need a storage.
        """
        verifiers.vertex.verify_pow(block)
        verifiers.block.verify_no_inputs(block)
        verifiers.vertex.verify_outputs(block)
        verifiers.block.verify_output_token_indexes(block)
        verifiers.block.verify_data(block)
        verifiers.vertex.verify_sigops_output(block)

    @classmethod
    def _verify_without_storage_merge_mined_block(cls, block: MergeMinedBlock, verifiers: VertexVerifiers) -> None:
        verifiers.merge_mined_block.verify_aux_pow(block)
        cls._verify_without_storage_block(block, verifiers)

    @classmethod
    def _verify_without_storage_tx(cls, tx: Transaction, verifiers: VertexVerifiers) -> None:
        """ Run all verifications that do not need a storage.
        """
        verifiers.vertex.verify_pow(tx)
        verifiers.tx.verify_number_of_inputs(tx)
        verifiers.vertex.verify_outputs(tx)
        verifiers.tx.verify_output_token_indexes(tx)
        verifiers.vertex.verify_sigops_output(tx)

    @classmethod
    def _verify_without_storage_token_creation_tx(
        cls,
        tx: TokenCreationTransaction,
        verifiers: VertexVerifiers
    ) -> None:
        cls._verify_without_storage_tx(tx, verifiers)
