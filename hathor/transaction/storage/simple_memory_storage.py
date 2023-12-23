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
from typing import Any

from hathor.transaction import Block, Transaction, TransactionMetadata
from hathor.transaction.base_transaction import BaseTransaction, tx_or_block_from_bytes
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId
from hathor.util import not_none


@dataclass(frozen=True, slots=True)
class _SimpleMemoryRecord:
    vertex_bytes: bytes
    vertex_metadata: dict[str, Any]


class SimpleMemoryStorage:
    """
    Instances of this class simply facilitate storing some data in memory, specifically for pre-fetched verification
    dependencies.
    """
    __slots__ = ('_blocks', '_transactions', '_best_block_tips')

    def __init__(self) -> None:
        self._blocks: dict[VertexId, _SimpleMemoryRecord] = {}
        self._transactions: dict[VertexId, _SimpleMemoryRecord] = {}
        self._best_block_tips: list[VertexId] = []

    @property
    def _vertices(self) -> dict[VertexId, _SimpleMemoryRecord]:
        """Blocks and Transactions together."""
        return {**self._blocks, **self._transactions}

    def get_block(self, block_id: VertexId) -> Block:
        """Return a block from the storage, throw if it's not found."""
        block = self._get_record(self._blocks, block_id)
        assert isinstance(block, Block)
        return block

    def get_transaction(self, tx_id: VertexId) -> Transaction:
        """Return a transaction from the storage, throw if it's not found."""
        tx = self._get_record(self._transactions, tx_id)
        assert isinstance(tx, Transaction)
        return tx

    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        """Return a vertex from the storage, throw if it's not found."""
        return self._get_record(self._vertices, vertex_id)

    def get_metadata(self, vertex_id: VertexId) -> TransactionMetadata:
        """Return vertex metadata from the storage."""
        return self.get_vertex(vertex_id).get_metadata()

    @staticmethod
    def _get_record(storage: dict[VertexId, _SimpleMemoryRecord], vertex_id: VertexId) -> BaseTransaction:
        """Return a record from a storage, throw if it's not found."""
        if record := storage.get(vertex_id):
            vertex = tx_or_block_from_bytes(record.vertex_bytes)
            metadata = TransactionMetadata.create_from_json(record.vertex_metadata)
            vertex._metadata = metadata
            return vertex

        raise TransactionDoesNotExist(f'Vertex "{vertex_id.hex()}" does not exist in this SimpleMemoryStorage.')

    def get_parent_block(self, block: Block) -> Block:
        """Get the parent block of a block."""
        parent_hash = block.get_block_parent_hash()

        return self.get_block(parent_hash)

    def add_vertices_from_storage(self, storage: TransactionStorage, ids: list[VertexId]) -> None:
        """
        Add multiple vertices to this storage. It automatically fetches data from the provided TransactionStorage
        and a list of ids.
        """
        for vertex_id in ids:
            self.add_vertex_from_storage(storage, vertex_id)

    def add_vertex_from_storage(self, storage: TransactionStorage, vertex_id: VertexId) -> None:
        """
        Add a vertex to this storage. It automatically fetches data from the provided TransactionStorage and vertex_id.
        """
        vertex = storage.get_transaction(vertex_id)

        self.add_vertex(vertex)

    def add_vertex(self, vertex: BaseTransaction) -> None:
        """Add a vertex to this storage."""
        vertex_id = not_none(vertex.hash)

        if vertex_id in self._vertices:
            return

        vertex_bytes = vertex.get_struct()
        metadata = vertex.get_metadata().to_json()
        record = _SimpleMemoryRecord(vertex_bytes, metadata)

        if isinstance(vertex, Block):
            self._blocks[vertex_id] = record
            return

        if isinstance(vertex, Transaction):
            self._transactions[vertex_id] = record
            return

        raise NotImplementedError

    def set_best_block_tips_from_storage(self, storage: TransactionStorage) -> None:
        tips = storage.get_best_block_tips()
        self.add_vertices_from_storage(storage, tips)
        self._best_block_tips = tips

    def get_best_block_tips(self) -> list[VertexId]:
        return self._best_block_tips
