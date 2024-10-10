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

from typing import Any

from intervaltree import Interval
from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.indexes.height_index import HeightInfo
from hathor.indexes.timestamp_index import RangeIdx
from hathor.p2p import P2PDependencies
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol
from hathor.transaction import Block, Vertex
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId
from hathor.util import not_none
from hathor.verification.verification_service import VerificationService
from hathor.vertex_handler import VertexHandler


class SingleProcessP2PDependencies(P2PDependencies):
    __slots__ = (
        '_tx_storage',
        '_vertex_handler',
        '_verification_service',
        '_pubsub',
        '_indexes',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        vertex_parser: VertexParser,
        tx_storage: TransactionStorage,
        vertex_handler: VertexHandler,
        verification_service: VerificationService,
        pubsub: PubSubManager,
    ) -> None:
        super().__init__(reactor=reactor, settings=settings, vertex_parser=vertex_parser)
        self._tx_storage = tx_storage
        self._vertex_handler = vertex_handler
        self._verification_service = verification_service
        self._pubsub = pubsub
        self._indexes = not_none(tx_storage.indexes)

    @override
    def on_new_vertex(self, vertex: Vertex, *, fails_silently: bool = True) -> bool:
        return self._vertex_handler.on_new_vertex(vertex=vertex, fails_silently=fails_silently)

    @override
    def verify_basic(self, vertex: Vertex) -> None:
        return self._verification_service.verify_basic(vertex)

    @override
    def publish(self, key: HathorEvents, **kwargs: Any) -> None:
        self._pubsub.publish(key, **kwargs)

    @override
    def get_genesis(self, vertex_id: VertexId) -> Vertex | None:
        return self._tx_storage.get_genesis(vertex_id)

    @override
    def get_vertex(self, vertex_id: VertexId) -> Vertex:
        return self._tx_storage.get_vertex(vertex_id)

    @override
    def get_block(self, block_id: VertexId) -> Block:
        return self._tx_storage.get_block(block_id)

    @override
    def get_latest_timestamp(self) -> int:
        return self._tx_storage.latest_timestamp

    @override
    def get_first_timestamp(self) -> int:
        return self._tx_storage.first_timestamp

    @override
    def vertex_exists(self, vertex_id: VertexId) -> bool:
        return self._tx_storage.transaction_exists(vertex_id)

    @override
    def can_validate_full(self, vertex: Vertex) -> bool:
        return self._tx_storage.can_validate_full(vertex)

    @override
    def get_merkle_tree(self, timestamp: int) -> tuple[bytes, list[bytes]]:
        return self._tx_storage.get_merkle_tree(timestamp)

    @override
    def get_hashes_and_next_idx(self, from_idx: RangeIdx, count: int) -> tuple[list[bytes], RangeIdx | None]:
        return self._indexes.sorted_all.get_hashes_and_next_idx(from_idx, count)

    @override
    def compare_bytes_with_local_vertex(self, vertex: Vertex) -> bool:
        return self._tx_storage.compare_bytes_with_local_tx(vertex)

    @override
    def get_best_block(self) -> Block:
        return self._tx_storage.get_best_block()

    @override
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        return self._tx_storage.get_n_height_tips(n_blocks)

    @override
    def get_tx_tips(self, timestamp: float | None = None) -> set[Interval]:
        return self._tx_storage.get_tx_tips(timestamp)

    @override
    def get_mempool_tips(self) -> set[VertexId]:
        return not_none(self._indexes.mempool_tips).get()

    @override
    def height_index_get(self, height: int) -> VertexId | None:
        return self._indexes.height.get(height)

    @override
    def get_parent_block(self, block: Block) -> Block:
        return self._tx_storage.get_parent_block(block)

    @override
    def get_best_block_tips(self) -> list[VertexId]:
        return self.get_best_block_tips()

    @override
    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        return self._tx_storage.partial_vertex_exists(vertex_id)
