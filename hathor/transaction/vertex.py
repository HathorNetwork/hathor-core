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
    """A simple generic wrapper around a BaseTransaction used to create each tag of the Vertex tagged union."""
    base_tx: T


class BlockType(_VertexWrapper[Block]):
    """Vertex wrapper for Block."""


class MergeMinedBlockType(_VertexWrapper[MergeMinedBlock]):
    """Vertex wrapper for MergeMinedBlock."""


class TransactionType(_VertexWrapper[Transaction]):
    """Vertex wrapper for Transaction."""


class TokenCreationTransactionType(_VertexWrapper[TokenCreationTransaction]):
    """Vertex wrapper for TokenCreationTransaction."""


"""
A Vertex algebraic sum type, or tagged union, that unifies all vertex types.

This is useful when dealing with vertices in functional code, for example when using `match` statements, so we don't
have problems with inheritance in `case` branches.
"""
Vertex: TypeAlias = BlockType | MergeMinedBlockType | TransactionType | TokenCreationTransactionType
