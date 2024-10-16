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
from twisted.protocols import amp
from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.indexes.height_index import HeightInfo
from hathor.indexes.timestamp_index import RangeIdx
from hathor.multiprocess.node_ipc_server import *
from hathor.p2p import P2PDependencies
from hathor.pubsub import HathorEvents
from hathor.reactor import ReactorProtocol
from hathor.transaction import Block, Vertex
from hathor.transaction.static_metadata import VertexStaticMetadata
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId


class MultiprocessP2PDependencies(P2PDependencies):
    __slots__ = (
        '_client',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        client: amp.AMP,
        vertex_parser: VertexParser,
    ) -> None:
        super().__init__(reactor=reactor, settings=settings, vertex_parser=vertex_parser)
        self._client = client

    @override
    async def on_new_vertex(self, vertex: Vertex, *, fails_silently: bool = True) -> bool:
        response = await self._client.callRemote(
            OnNewVertex,
            vertex_bytes=bytes(vertex),
            fails_silently=fails_silently
        )
        return response['success']

    @override
    def verify_basic(self, vertex: Vertex) -> None:
        # TODO
        return

    @override
    def publish(self, key: HathorEvents, **kwargs: Any) -> None:
        # TODO
        return

    @override
    def get_genesis(self, vertex_id: VertexId) -> Vertex | None:
        # return self._tx_storage.get_genesis(vertex_id)
        raise NotImplementedError

    @override
    async def get_vertex(self, vertex_id: VertexId) -> Vertex:
        # return self._tx_storage.get_vertex(vertex_id)
        response = await self._client.callRemote(GetVertex, vertex_id=vertex_id)
        vertex_bytes, static_metadata_bytes = response['vertex_bytes']
        vertex = self.vertex_parser.deserialize(vertex_bytes)
        static_metadata = VertexStaticMetadata.from_bytes(static_metadata_bytes, target=vertex)
        vertex.set_static_metadata(static_metadata)
        return vertex

    @override
    def get_block(self, block_id: VertexId) -> Block:
        # return self._tx_storage.get_block(block_id)
        raise NotImplementedError

    @override
    def get_latest_timestamp(self) -> int:
        # return self._tx_storage.latest_timestamp
        raise NotImplementedError

    @override
    def get_first_timestamp(self) -> int:
        # return self._tx_storage.first_timestamp
        raise NotImplementedError

    @override
    async def vertex_exists(self, vertex_id: VertexId) -> bool:
        # return self._tx_storage.transaction_exists(vertex_id)
        response = await self._client.callRemote(VertexExists, vertex_id=vertex_id)
        return response['exists']


    @override
    async def can_validate_full(self, vertex: Vertex) -> bool:
        # return self._tx_storage.can_validate_full(vertex)
        response = await self._client.callRemote(CanValidateFull, vertex_bytes=bytes(vertex))
        return response['can_validate_full']

    @override
    def get_merkle_tree(self, timestamp: int) -> tuple[bytes, list[bytes]]:
        # return self._tx_storage.get_merkle_tree(timestamp)
        raise NotImplementedError

    @override
    def get_hashes_and_next_idx(self, from_idx: RangeIdx, count: int) -> tuple[list[bytes], RangeIdx | None]:
        # return self._indexes.sorted_all.get_hashes_and_next_idx(from_idx, count)
        raise NotImplementedError

    @override
    def compare_bytes_with_local_vertex(self, vertex: Vertex) -> bool:
        # return self._tx_storage.compare_bytes_with_local_tx(vertex)
        raise NotImplementedError

    @override
    async def get_best_block(self) -> Block:
        # return self._tx_storage.get_best_block()
        response = await self._client.callRemote(GetBestBlock)
        vertex_bytes, static_metadata_bytes = response['vertex_bytes']
        block = self.vertex_parser.deserialize(vertex_bytes)
        static_metadata = VertexStaticMetadata.from_bytes(static_metadata_bytes, target=block)
        block.set_static_metadata(static_metadata)
        return block

    @override
    async def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        # return self._tx_storage.get_n_height_tips(n_blocks)
        response = await self._client.callRemote(GetNHeightTips, n_blocks=n_blocks)
        return [HeightInfo(item['height'], item['id']) for item in response['tips']]

    @override
    def get_tx_tips(self, timestamp: float | None = None) -> set[Interval]:
        # return self._tx_storage.get_tx_tips(timestamp)
        raise NotImplementedError

    @override
    async def get_mempool_tips(self) -> set[VertexId]:
        # return not_none(self._indexes.mempool_tips).get()
        response = await self._client.callRemote(GetMempoolTips)
        return response['mempool_tips']

    @override
    def height_index_get(self, height: int) -> VertexId | None:
        # return self._indexes.height.get(height)
        raise NotImplementedError

    @override
    def get_parent_block(self, block: Block) -> Block:
        # return self._tx_storage.get_parent_block(block)
        raise NotImplementedError

    @override
    def get_best_block_tips(self) -> list[VertexId]:
        # return self._tx_storage.get_best_block_tips()
        raise NotImplementedError

    @override
    async def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        # return self._tx_storage.partial_vertex_exists(vertex_id)
        response = await self._client.callRemote(PartialVertexExists, vertex_id=vertex_id)
        return response['exists']
