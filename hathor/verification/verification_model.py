#  Copyright 2024 Hathor Labs
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

from dataclasses import dataclass
from typing import Generic, TypeAlias, TypeVar

from typing_extensions import assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, TxVersion
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.transaction import Transaction
from hathor.verification.verification_dependencies import (
    BasicBlockDependencies,
    BlockDependencies,
    TransactionDependencies,
)

T = TypeVar('T', bound=BaseTransaction)
BasicDepsT = TypeVar('BasicDepsT')
DepsT = TypeVar('DepsT')


@dataclass(frozen=True, slots=True)
class _VerificationModel(Generic[T, BasicDepsT, DepsT]):
    """A simple dataclass that wraps a vertex and all dependencies necessary for its verification."""
    vertex: T
    basic_deps: BasicDepsT
    deps: DepsT | None


@dataclass(frozen=True, slots=True)
class VerificationBlock(_VerificationModel[Block, BasicBlockDependencies, BlockDependencies]):
    """A simple dataclass that wraps a Block and all dependencies necessary for its verification."""


@dataclass(frozen=True, slots=True)
class VerificationMergeMinedBlock(_VerificationModel[MergeMinedBlock, BasicBlockDependencies, BlockDependencies]):
    """A simple dataclass that wraps a MergeMinedBlock and all dependencies necessary for its verification."""


@dataclass(frozen=True, slots=True)
class VerificationTransaction(_VerificationModel[Transaction, None, TransactionDependencies]):
    """A simple dataclass that wraps a Transaction and all dependencies necessary for its verification."""


@dataclass(frozen=True, slots=True)
class VerificationTokenCreationTransaction(
    _VerificationModel[TokenCreationTransaction, None, TransactionDependencies]
):
    """A simple dataclass that wraps a TokenCreationTransaction and all dependencies necessary for its verification."""


"""A type alias representing an union type for verification models for all vertex types."""
VerificationModel: TypeAlias = (
    VerificationBlock | VerificationMergeMinedBlock | VerificationTransaction | VerificationTokenCreationTransaction
)


def get_verification_model_from_storage(
    vertex: BaseTransaction,
    storage: TransactionStorage,
    *,
    daa: DifficultyAdjustmentAlgorithm,
    skip_weight_verification: bool = False,
    only_basic: bool = False
) -> VerificationModel:
    """Create a verification model instance for a vertex using dependencies from a storage."""
    # We assert with type() instead of isinstance() because each subclass has a specific branch.
    match vertex.version:
        case TxVersion.REGULAR_BLOCK:
            assert type(vertex) is Block
            basic_deps, deps = _get_block_deps(
                vertex,
                storage=storage,
                daa=daa,
                skip_weight_verification=skip_weight_verification,
                only_basic=only_basic,
            )
            return VerificationBlock(
                vertex=vertex,
                basic_deps=basic_deps,
                deps=deps,
            )

        case TxVersion.MERGE_MINED_BLOCK:
            assert type(vertex) is MergeMinedBlock
            basic_deps, deps = _get_block_deps(
                vertex,
                storage=storage,
                daa=daa,
                skip_weight_verification=skip_weight_verification,
                only_basic=only_basic,
            )
            return VerificationMergeMinedBlock(
                vertex=vertex,
                basic_deps=basic_deps,
                deps=deps,
            )

        case TxVersion.REGULAR_TRANSACTION:
            assert type(vertex) is Transaction
            return VerificationTransaction(
                vertex=vertex,
                basic_deps=None,
                deps=_get_tx_deps(vertex, storage=storage, only_basic=only_basic),
            )

        case TxVersion.TOKEN_CREATION_TRANSACTION:
            assert type(vertex) is TokenCreationTransaction
            return VerificationTokenCreationTransaction(
                vertex=vertex,
                basic_deps=None,
                deps=_get_tx_deps(vertex, storage=storage, only_basic=only_basic),
            )

        case _:
            assert_never(vertex.version)


def _get_block_deps(
    block: Block,
    *,
    storage: TransactionStorage,
    daa: DifficultyAdjustmentAlgorithm,
    skip_weight_verification: bool,
    only_basic: bool
) -> tuple[BasicBlockDependencies, BlockDependencies | None]:
    """Create the necessary dependencies instances for a Block, using a storage."""
    basic_deps = BasicBlockDependencies.create_from_storage(
        block,
        storage=storage,
        daa=daa,
        skip_weight_verification=skip_weight_verification,
    )
    deps = None
    if not only_basic:
        deps = BlockDependencies.create_from_storage(block, storage=storage)

    return basic_deps, deps


def _get_tx_deps(tx: Transaction, *, storage: TransactionStorage, only_basic: bool) -> TransactionDependencies | None:
    """Create the necessary dependencies instances for a Transaction, using a storage."""
    deps = None
    if not only_basic:
        deps = TransactionDependencies.create_from_storage(tx, storage)

    return deps
