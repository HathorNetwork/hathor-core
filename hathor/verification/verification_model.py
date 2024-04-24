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
from hathor.feature_activation.feature_service import FeatureService
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
    vertex: T
    basic_deps: BasicDepsT
    deps: DepsT | None


@dataclass(frozen=True, slots=True)
class VerificationBlock(_VerificationModel[Block, BasicBlockDependencies, BlockDependencies]):
    # TODO: If we send bytes over multiprocessing instead of objects, we may increase performance
    def clone(self) -> 'VerificationBlock':
        return VerificationBlock(
            vertex=self.vertex.clone(include_storage=False, include_metadata=False),
            basic_deps=self.basic_deps.clone(),
            deps=self.deps.clone() if self.deps else None
        )


@dataclass(frozen=True, slots=True)
class VerificationMergeMinedBlock(_VerificationModel[MergeMinedBlock, BasicBlockDependencies, BlockDependencies]):
    def clone(self) -> 'VerificationMergeMinedBlock':
        return VerificationMergeMinedBlock(
            vertex=self.vertex.clone(include_storage=False, include_metadata=False),
            basic_deps=self.basic_deps.clone(),
            deps=self.deps.clone() if self.deps else None
        )


@dataclass(frozen=True, slots=True)
class VerificationTransaction(_VerificationModel[Transaction, None, TransactionDependencies]):
    def clone(self) -> 'VerificationTransaction':
        return VerificationTransaction(
            vertex=self.vertex.clone(include_storage=False, include_metadata=False),
            basic_deps=None,
            deps=self.deps.clone() if self.deps else None
        )


@dataclass(frozen=True, slots=True)
class VerificationTokenCreationTransaction(
    _VerificationModel[TokenCreationTransaction, None, TransactionDependencies]
):
    def clone(self) -> 'VerificationTokenCreationTransaction':
        return VerificationTokenCreationTransaction(
            vertex=self.vertex.clone(include_storage=False, include_metadata=False),
            basic_deps=None,
            deps=self.deps.clone() if self.deps else None
        )


VerificationModel: TypeAlias = (
    VerificationBlock | VerificationMergeMinedBlock | VerificationTransaction | VerificationTokenCreationTransaction
)


def get_verification_model_from_storage(
    vertex: BaseTransaction,
    storage: TransactionStorage,
    *,
    daa: DifficultyAdjustmentAlgorithm,
    feature_service: FeatureService,
    skip_weight_verification: bool = False,
    only_basic: bool = False
) -> VerificationModel:
    # We assert with type() instead of isinstance() because each subclass has a specific branch.
    match vertex.version:
        case TxVersion.REGULAR_BLOCK:
            assert type(vertex) is Block
            basic_deps, deps = _get_block_deps(
                vertex,
                storage=storage,
                daa=daa,
                feature_service=feature_service,
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
                feature_service=feature_service,
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
    feature_service: FeatureService,
    skip_weight_verification: bool,
    only_basic: bool
) -> tuple[BasicBlockDependencies, BlockDependencies | None]:
    basic_deps = BasicBlockDependencies.create_from_storage(
        block,
        storage=storage,
        daa=daa,
        skip_weight_verification=skip_weight_verification,
    )
    deps = None
    if not only_basic:
        deps = BlockDependencies.create_from_storage(
            block,
            storage=storage,
            feature_service=feature_service,
        )

    return basic_deps, deps


def _get_tx_deps(tx: Transaction, *, storage: TransactionStorage, only_basic: bool) -> TransactionDependencies | None:
    deps = None
    if not only_basic:
        deps = TransactionDependencies.create_from_storage(tx, storage)

    return deps
