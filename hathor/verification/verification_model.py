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

from hathor.transaction import BaseTransaction, Block, MergeMinedBlock
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
    pass


@dataclass(frozen=True, slots=True)
class VerificationMergeMinedBlock(_VerificationModel[MergeMinedBlock, BasicBlockDependencies, BlockDependencies]):
    pass


@dataclass(frozen=True, slots=True)
class VerificationTransaction(_VerificationModel[Transaction, None, TransactionDependencies]):
    pass


@dataclass(frozen=True, slots=True)
class VerificationTokenCreationTransaction(
    _VerificationModel[TokenCreationTransaction, None, TransactionDependencies]
):
    pass


VerificationModel: TypeAlias = (
    VerificationBlock | VerificationMergeMinedBlock | VerificationTransaction | VerificationTokenCreationTransaction
)
