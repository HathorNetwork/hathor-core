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

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols import amp

from hathor.exception import InvalidNewTransaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.types import VertexId
from hathor.util import not_none
from hathor.vertex_handler import VertexHandler


class OnNewVertex(amp.Command):
    arguments = [(b'vertex_bytes', amp.String()), (b'fails_silently', amp.Boolean())]
    response = [(b'success', amp.Boolean())]
    errors = {InvalidNewTransaction: b'INVALID_NEW_TX'}


class GetBestBlock(amp.Command):
    response = [(b'vertex_bytes', amp.ListOf(amp.String()))]


class GetMempoolTips(amp.Command):
    response = [(b'mempool_tips', amp.ListOf(amp.String()))]


class PartialVertexExists(amp.Command):
    arguments = [(b'vertex_id', amp.String())]
    response = [(b'exists', amp.Boolean())]


class VertexExists(amp.Command):
    arguments = [(b'vertex_id', amp.String())]
    response = [(b'exists', amp.Boolean())]


class CanValidateFull(amp.Command):
    arguments = [(b'vertex_bytes', amp.String())]
    response = [(b'can_validate_full', amp.Boolean())]


class GetNHeightTips(amp.Command):
    arguments = [(b'n_blocks', amp.Integer())]
    response = [(b'tips', amp.AmpList([
        (b'height', amp.Integer()),
        (b'id', amp.String())
    ]))]


class GetVertex(amp.Command):
    arguments = [(b'vertex_id', amp.String())]
    response = [(b'vertex_bytes', amp.ListOf(amp.String()))]


class NodeIpcServer(amp.AMP):
    __slots__ = ('vertex_parser', 'vertex_handler', 'tx_storage')

    def __init__(
        self,
        *,
        vertex_parser: VertexParser,
        vertex_handler: VertexHandler,
        tx_storage: TransactionStorage,
    ) -> None:
        super().__init__()
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler
        self.tx_storage = tx_storage
        self.indexes = not_none(tx_storage.indexes)

    @OnNewVertex.responder
    def on_new_vertex(self, vertex_bytes: bytes, fails_silently: bool) -> dict[str, Any]:
        vertex = self.vertex_parser.deserialize(vertex_bytes)
        success = self.vertex_handler.on_new_vertex(vertex, fails_silently=fails_silently)
        return dict(success=success)

    @GetBestBlock.responder
    def get_best_block(self) -> dict[str, Any]:
        vertex = self.tx_storage.get_best_block()
        return dict(vertex_bytes=[bytes(vertex), vertex.static_metadata.json_dumpb()])

    @GetMempoolTips.responder
    def get_mempool_tips(self) -> dict[str, Any]:
        return dict(
            mempool_tips=not_none(self.indexes.mempool_tips).get()
        )

    @PartialVertexExists.responder
    def partial_vertex_exists(self, vertex_id: VertexId) -> dict[str, Any]:
        return dict(
            exists=self.tx_storage.partial_vertex_exists(vertex_id)
        )

    @VertexExists.responder
    def vertex_exists(self, vertex_id: VertexId) -> dict[str, Any]:
        return dict(
            exists=self.tx_storage.transaction_exists(vertex_id)
        )

    @CanValidateFull.responder
    def can_validate_full(self, vertex_bytes: bytes) -> dict[str, Any]:
        vertex = self.vertex_parser.deserialize(vertex_bytes)
        return dict(
            can_validate_full=self.tx_storage.can_validate_full(vertex)
        )

    @GetNHeightTips.responder
    def get_n_height_tips(self, n_blocks: int) -> dict[str, Any]:
        tips = self.tx_storage.get_n_height_tips(n_blocks)
        return dict(
            tips=[
                dict(height=info.height, id=info.id) for info in tips
            ]
        )

    @GetVertex.responder
    def get_vertex(self, vertex_id: VertexId) -> dict[str, Any]:
        vertex = self.tx_storage.get_vertex(vertex_id)
        return dict(vertex_bytes=[bytes(vertex), vertex.static_metadata.json_dumpb()])


class NodeIpcServerFactory(ServerFactory):
    __slots__ = ('vertex_parser', 'vertex_handler', 'tx_storage')

    def __init__(self, *, vertex_parser: VertexParser, vertex_handler: VertexHandler, tx_storage: TransactionStorage) -> None:
        super().__init__()
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler
        self.tx_storage = tx_storage

    def buildProtocol(self, addr: IAddress) -> NodeIpcServer:
        p = NodeIpcServer(vertex_parser=self.vertex_parser, vertex_handler=self.vertex_handler, tx_storage=self.tx_storage)
        p.factory = self
        return p
