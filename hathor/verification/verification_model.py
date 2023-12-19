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

from dataclasses import dataclass
from typing import Generic, TypeAlias, TypeVar

from typing_extensions import Self

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import BlockSignalingState, FeatureActivationIsDisabled, FeatureService
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, TransactionMetadata, TxInput
from hathor.transaction.exceptions import IncorrectParents, InexistentInput
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.simple_memory_storage import SimpleMemoryStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.transaction import RewardLockedInfo, TokenInfo, Transaction
from hathor.types import TokenUid
from hathor.util import not_none


@dataclass(frozen=True, slots=True, kw_only=True)
class VertexDependencies:
    """A dataclass of dependencies necessary for vertex verification."""
    storage: SimpleMemoryStorage


@dataclass(frozen=True, slots=True, kw_only=True)
class BlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for block verification."""
    metadata: TransactionMetadata
    signaling_state: BlockSignalingState

    @classmethod
    def create(cls, block: Block, feature_service: FeatureService) -> Self:
        """Create a dependencies instance from a block and a DAA instance."""

        signaling_state = feature_service.is_signaling_mandatory_features(block)

        return cls(
            storage=SimpleMemoryStorage(),
            metadata=block.get_metadata(),
            signaling_state=signaling_state,
        )


VertexT = TypeVar('VertexT', bound=BaseTransaction)
DepsT = TypeVar('DepsT', bound=VertexDependencies)


@dataclass(frozen=True, slots=True)
class _VertexVerificationModel(Generic[VertexT, DepsT]):
    """
    The model used for vertex verification. Includes the vertex itself and the respective necessary dependencies.
    It is generic over the vertex type and dependencies type, and then reified for each one of the existing types.
    """
    vertex: VertexT
    deps: DepsT | None


class BlockVerification(_VertexVerificationModel[Block, BlockDependencies]):
    """Vertex verification model reified for Block."""


class MergeMinedBlockVerification(_VertexVerificationModel[MergeMinedBlock, BlockDependencies]):
    """Vertex verification model reified for MergeMinedBlock."""


class TxVerification(_VertexVerificationModel[Transaction, TransactionDependencies]):
    """Vertex verification model reified for Transaction."""


class TokenCreationTxVerification(_VertexVerificationModel[TokenCreationTransaction, TransactionDependencies]):
    """Vertex verification model reified for TokenCreationTransaction."""


# An algebraic sum type that unifies all verification models.
VertexVerificationModel: TypeAlias = (
    BlockVerification | MergeMinedBlockVerification | TxVerification | TokenCreationTxVerification
)
