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

from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction
from hathor.transaction.token_creation_tx import TokenCreationTransaction

T = TypeVar('T', bound=BaseTransaction)


@dataclass(frozen=True, slots=True)
class _VertexWrapper(Generic[T]):
    """
    The model used for vertex verification. Includes the vertex itself and the respective necessary dependencies.
    It is generic over the vertex type and dependencies type, and then reified for each one of the existing types.
    """
    base_tx: T


class BlockType(_VertexWrapper[Block]):
    """Vertex verification model reified for Block."""


class MergeMinedBlockType(_VertexWrapper[MergeMinedBlock]):
    """Vertex verification model reified for MergeMinedBlock."""


class TransactionType(_VertexWrapper[Transaction]):
    """Vertex verification model reified for Transaction."""


class TokenCreationTransactionType(_VertexWrapper[TokenCreationTransaction]):
    """Vertex verification model reified for TokenCreationTransaction."""


"""
A Vertex algebraic sum type that unifies all vertex types by using a `NewType` for each one, which introduces almost no
runtime overhead.

This is useful when dealing with vertices in functional code, for example when using `match` statements, so we don't
have problems with inheritance in `case` branches.
"""
Vertex: TypeAlias = BlockType | MergeMinedBlockType | TransactionType | TokenCreationTransactionType
