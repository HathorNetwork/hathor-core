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

from abc import ABC, abstractmethod
from typing import Any

from intervaltree import Interval

from hathor.conf.settings import HathorSettings
from hathor.indexes.height_index import HeightInfo
from hathor.indexes.timestamp_index import RangeIdx
from hathor.pubsub import HathorEvents
from hathor.reactor import ReactorProtocol
from hathor.transaction import Block, Vertex
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId


class P2PDependencies(ABC):
    """
    This abstract class serves as an interface for all communications between P2P-related classes
    and the rest of the full node.
    """

    __slots__ = ('reactor', 'settings', 'vertex_parser')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        vertex_parser: VertexParser,
    ) -> None:
        self.reactor = reactor
        self.settings = settings
        self.vertex_parser = vertex_parser

    @abstractmethod
    async def on_new_vertex(self, vertex: Vertex, *, fails_silently: bool = True) -> bool:
        raise NotImplementedError

    @abstractmethod
    def verify_basic(self, vertex: Vertex) -> None:
        raise NotImplementedError

    @abstractmethod
    def publish(self, key: HathorEvents, **kwargs: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_genesis(self, vertex_id: VertexId) -> Vertex | None:
        raise NotImplementedError

    @abstractmethod
    def get_vertex(self, vertex_id: VertexId) -> Vertex:
        raise NotImplementedError

    @abstractmethod
    def get_block(self, block_id: VertexId) -> Block:
        raise NotImplementedError

    @abstractmethod
    def get_latest_timestamp(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_first_timestamp(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def vertex_exists(self, vertex_id: VertexId) -> bool:
        raise NotImplementedError

    @abstractmethod
    def can_validate_full(self, vertex: Vertex) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_merkle_tree(self, timestamp: int) -> tuple[bytes, list[bytes]]:
        raise NotImplementedError

    @abstractmethod
    def get_hashes_and_next_idx(self, from_idx: RangeIdx, count: int) -> tuple[list[bytes], RangeIdx | None]:
        raise NotImplementedError

    @abstractmethod
    def compare_bytes_with_local_vertex(self, vertex: Vertex) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_best_block(self) -> Block:
        raise NotImplementedError

    @abstractmethod
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        raise NotImplementedError

    @abstractmethod
    def get_tx_tips(self, timestamp: float | None = None) -> set[Interval]:
        raise NotImplementedError

    @abstractmethod
    def get_mempool_tips(self) -> set[VertexId]:
        raise NotImplementedError

    @abstractmethod
    def height_index_get(self, height: int) -> VertexId | None:
        raise NotImplementedError

    @abstractmethod
    def get_parent_block(self, block: Block) -> Block:
        raise NotImplementedError

    @abstractmethod
    def get_best_block_tips(self) -> list[VertexId]:
        raise NotImplementedError

    @abstractmethod
    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        raise NotImplementedError
