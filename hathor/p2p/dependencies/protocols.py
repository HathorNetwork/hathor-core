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

from typing import Protocol

from hathor.indexes.height_index import HeightInfo
from hathor.transaction import Block, Vertex
from hathor.types import VertexId


class P2PVertexHandlerProtocol(Protocol):
    """Abstract the VertexHandler as a Python protocol to be used in P2P classes."""

    def on_new_vertex(self, vertex: Vertex, *, fails_silently: bool = True) -> bool: ...


class P2PVerificationServiceProtocol(Protocol):
    """Abstract the VerificationService as a Python protocol to be used in P2P classes."""

    def verify_basic(self, vertex: Vertex) -> None: ...


class P2PTransactionStorageProtocol(Protocol):
    """Abstract the TransactionStorage as a Python protocol to be used in P2P classes."""

    def get_vertex(self, vertex_id: VertexId) -> Vertex: ...
    def get_block(self, block_id: VertexId) -> Block: ...
    def transaction_exists(self, vertex_id: VertexId) -> bool: ...
    def can_validate_full(self, vertex: Vertex) -> bool: ...
    def compare_bytes_with_local_tx(self, vertex: Vertex) -> bool: ...
    def get_best_block(self) -> Block: ...
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]: ...
    def get_mempool_tips(self) -> set[VertexId]: ...
    def get_block_id_by_height(self, height: int) -> VertexId | None: ...
    def partial_vertex_exists(self, vertex_id: VertexId) -> bool: ...
