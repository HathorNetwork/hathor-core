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

from structlog import get_logger
from typing_extensions import override

from hathor.p2p.protocol import HathorProtocol
from hathor.transaction import Block, Transaction, Vertex
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId

logger = get_logger()


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
    __slots__ = (
        '_log',
        '_protocol',
        '_tx_storage',
        '_mempool_tips_index',
    )

    def __init__(self, *, protocol: HathorProtocol, tx_storage: TransactionStorage) -> None:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        self._log = logger.new()
        self._protocol = protocol
        self._tx_storage = tx_storage
        self._mempool_tips_index = tx_storage.indexes.mempool_tips

    def get_mempool_tips(self) -> set[VertexId]:
        return self._mempool_tips_index.get()

    def get_local_best_block(self) -> Block:
        return self.get_best_block()

    def get_best_block(self) -> Block:
        return self._tx_storage.get_best_block()

    def get_local_block_by_height(self, height: int) -> Block | None:
        return self.get_block_by_height(height)

    def get_block_by_height(self, height: int) -> Block | None:
        return self._tx_storage.get_block_by_height(height)

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
    __slots__ = (
        '_blocks',
        '_blocks_by_height',
        '_transactions',
        '_is_reset',
    )

    def __init__(self, *, protocol: HathorProtocol, tx_storage: TransactionStorage) -> None:
        super().__init__(protocol=protocol, tx_storage=tx_storage)
        self._blocks: dict[VertexId, Block] = {}
        self._blocks_by_height: dict[int, Block] = {}
        self._transactions: dict[VertexId, Transaction] = {}
        self._is_reset: bool = True

    @property
    def _vertices(self) -> dict[VertexId, Vertex]:
        return {**self._blocks, **self._transactions}

    def add_new_vertex(self, vertex: Vertex) -> None:
        """Add a new vertex to this storage's memory, that is, a vertex that has been received but has not yet been
        handled."""
        self._is_reset = False
        match vertex:
            case Transaction():
                self._transactions[vertex.hash] = vertex
            case Block():
                self._blocks[vertex.hash] = vertex
                self._blocks_by_height[vertex.static_metadata.height] = vertex

    def complete_vertex(self, vertex: Vertex, result: bool) -> None:
        """
        A callback that should be called when the handling of a vertex has been completed.
        It removes the vertex from this storage's memory (since it is now in the persisted storage).
        If there's been an error in the vertex handling, it also resets the storage and the connection.
        """
        if self._is_reset:
            return
        if not result:
            self._reset()
            return

        match vertex:
            case Transaction():
                del self._transactions[vertex.hash]
            case Block():
                del self._blocks[vertex.hash]
                self._blocks_by_height = {
                    height: vertex_id
                    for height, vertex_id in self._blocks_by_height.items()
                    if vertex_id != vertex.hash
                }

    def _reset(self) -> None:
        """Reset this storage by cleaning its memory and resetting the connection."""
        self._blocks = {}
        self._blocks_by_height = {}
        self._transactions = {}
        self._protocol.disconnect(force=True)
        self._is_reset = True

    @override
    def get_local_best_block(self) -> Block:
        best_block = self._tx_storage.get_best_block()

        for block in self._blocks.values():
            if block.static_metadata.height > best_block.static_metadata.height:
                best_block = block

        return best_block

    @override
    def get_local_block_by_height(self, height: int) -> Block | None:
        if storage_block := self._tx_storage.get_block_by_height(height):
            return storage_block

        return self._blocks_by_height.get(height)

    @override
    def local_partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self._tx_storage.allow_partially_validated_context():
            if self._tx_storage.transaction_exists(vertex_id):
                return True

        if vertex_id in self._vertices:
            return True

        return False

    @override
    def local_vertex_exists(self, vertex_id: VertexId) -> bool:
        if self._tx_storage.transaction_exists(vertex_id):
            return True

        if vertex_id in self._vertices:
            return True

        return False

    @override
    def compare_bytes_with_local_tx(self, tx: Vertex) -> bool:
        try:
            return self._tx_storage.compare_bytes_with_local_tx(tx)
        except TransactionDoesNotExist:
            pass

        if memory_tx := self._vertices.get(tx.hash):
            return bytes(tx) == bytes(memory_tx)

        raise TransactionDoesNotExist(tx.hash)

    @override
    def get_local_vertex(self, vertex_id: VertexId) -> Vertex:
        try:
            return self._tx_storage.get_vertex(vertex_id)
        except TransactionDoesNotExist:
            pass

        if memory_vertex := self._vertices.get(vertex_id):
            return memory_vertex

        raise TransactionDoesNotExist(vertex_id)

    @override
    def get_local_block(self, block_id: VertexId) -> Block:
        try:
            return self._tx_storage.get_block(block_id)
        except TransactionDoesNotExist:
            pass

        if block := self._blocks.get(block_id):
            return block

        raise TransactionDoesNotExist(block_id)

    @override
    def local_can_validate_full(self, vertex: Vertex) -> bool:
        deps = vertex.get_all_dependencies()
        return all(self.local_vertex_exists(dep) for dep in deps)
