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

from hathor.transaction import Block, Vertex
from hathor.transaction.storage import TransactionStorage
from hathor.types import VertexId


class P2PStorage:
    """
    This class represents a single point of contact for sync-v2 interacting with the storage and indexes.
    Every time sync-v2 needs to retrieve some info from the storage, it should call one of the methods in this class.

    It is basically a forward to storage methods, however it introduces the concept of a "local" version for some
    methods. The local version of a method returns data based on a single peer's perspective, while non-local methods
    return data directly from the storage.

    This class is to be used with synchronous sync-v2. Every time a new vertex is received, it is synchronously
    handled, and therefore the next vertex is only received after the previous vertex has been handled and saved in the
    storage. This means that in this class, every local method is simply a forward to the respective non-local method.

    Generally, local methods should be called every time the agent needs to retrieve data for its own downloading
    process. Conversely, non-local methods should be called when the agent is sending data to another peer.

    The `AsyncP2PStorage` subclass deals with asynchronous sync-v2, implementing special handling for local methods.
    """
    __slots__ = ('_tx_storage', '_mempool_tips_index', '_height_index')

    def __init__(self, *, tx_storage: TransactionStorage) -> None:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        assert tx_storage.indexes.height is not None
        self._tx_storage = tx_storage
        self._mempool_tips_index = tx_storage.indexes.mempool_tips
        self._height_index = tx_storage.indexes.height

    def get_mempool_tips(self) -> set[VertexId]:
        return self._mempool_tips_index.get()

    def get_local_best_block(self) -> Block:
        return self.get_best_block()

    def get_best_block(self) -> Block:
        return self._tx_storage.get_best_block()

    def get_local_block_by_height(self, height: int) -> VertexId | None:
        return self.get_block_by_height(height)

    def get_block_by_height(self, height: int) -> VertexId | None:
        return self._height_index.get(height)

    def local_partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self._tx_storage.allow_partially_validated_context():
            return self._tx_storage.transaction_exists(vertex_id)

    def local_vertex_exists(self, vertex_id: VertexId) -> bool:
        return self._tx_storage.transaction_exists(vertex_id)

    def get_genesis(self, vertex_id: VertexId) -> Vertex | None:
        return self._tx_storage.get_genesis(vertex_id)

    def compare_bytes_with_local_tx(self, tx: Vertex) -> bool:
        return self._tx_storage.compare_bytes_with_local_tx(tx)

    def get_local_vertex(self, vertex_id: VertexId) -> Vertex:
        return self.get_vertex(vertex_id)

    def get_vertex(self, vertex_id: VertexId) -> Vertex:
        return self._tx_storage.get_vertex(vertex_id)

    def get_local_block(self, block_id: VertexId) -> Block:
        return self.get_block(block_id)

    def get_block(self, block_id: VertexId) -> Block:
        return self._tx_storage.get_block(block_id)

    def get_parent_block(self, block: Block) -> Block:
        return self._tx_storage.get_parent_block(block)

    def get_best_block_tips(self) -> list[VertexId]:
        return self._tx_storage.get_best_block_tips()

    def local_can_validate_full(self, vertex: Vertex) -> bool:
        return self._tx_storage.can_validate_full(vertex)


class AsyncP2PStorage(P2PStorage):
    """
    This class represents a single point of contact for sync-v2 interacting with the storage and indexes.
    Every time sync-v2 needs to retrieve some info from the storage, it should call one of the methods in this class.

    It is basically a forward to storage methods, however it introduces the concept of a "local" version for some
    methods. The local version of a method returns data based on a single peer's perspective, while non-local methods
    return data directly from the storage.

    This class is to be used with asynchronous sync-v2. It helps progress the sync without waiting for handling of
    vertices, therefore there is a set of handled vertices already saved in the storage, and a set of not-yet-handled
    vertices that are only local to this agent. This means that every local method is implemented by checking not only
    the storage, but also vertices that are still waiting to be handled, in memory.

    Generally, local methods should be called every time the agent needs to retrieve data for its own downloading
    process. Conversely, non-local methods should be called when the agent is sending data to another peer.

    The `P2PStorage` superclass deals with synchronous sync-v2.
    """
    # TODO: To be implemented
