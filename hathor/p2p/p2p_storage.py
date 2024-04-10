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

from hathor.transaction import BaseTransaction, Block
from hathor.transaction.storage import TransactionStorage
from hathor.types import VertexId


class P2PStorage:
    __slots__ = ('_tx_storage', '_mempool_tips_index', '_height_index')

    def __init__(self, tx_storage: TransactionStorage) -> None:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        assert tx_storage.indexes.height is not None
        self._tx_storage = tx_storage
        self._mempool_tips_index = tx_storage.indexes.mempool_tips
        self._height_index = tx_storage.indexes.height

    def get_mempool_tips(self) -> set[VertexId]:
        return self._mempool_tips_index.get()

    def get_best_block(self) -> Block:
        return self._tx_storage.get_best_block()

    def get_block_by_height(self, height: int) -> VertexId | None:
        return self._height_index.get(height)

    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self._tx_storage.allow_partially_validated_context():
            return self._tx_storage.transaction_exists(vertex_id)

    def get_transaction(self, vertex_id: VertexId) -> BaseTransaction:
        return self._tx_storage.get_transaction(vertex_id)

    def transaction_exists(self, vertex_id: VertexId) -> bool:
        return self._tx_storage.transaction_exists(vertex_id)

    def get_genesis(self, vertex_id: VertexId) -> BaseTransaction | None:
        return self._tx_storage.get_genesis(vertex_id)

    def compare_bytes_with_local_tx(self, tx: BaseTransaction) -> bool:
        return self._tx_storage.compare_bytes_with_local_tx(tx)

    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        return self._tx_storage.get_vertex(vertex_id)

    def get_block(self, block_id: VertexId) -> Block:
        return self._tx_storage.get_block(block_id)

    def get_parent_block(self, block: Block) -> Block:
        return self._tx_storage.get_parent_block(block)

    def get_best_block_tips(self) -> list[VertexId]:
        return self._tx_storage.get_best_block_tips()

    def can_validate_full(self, vertex: BaseTransaction) -> bool:
        return self._tx_storage.can_validate_full(vertex)
