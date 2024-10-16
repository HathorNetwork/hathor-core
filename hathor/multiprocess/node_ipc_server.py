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
from hathor.transaction.vertex_parser import VertexParser
from hathor.vertex_handler import VertexHandler


class OnNewVertex(amp.Command):
    arguments = [(b'vertex_bytes', amp.String()), (b'fails_silently', amp.Boolean())]
    response = [(b'success', amp.Boolean())]
    errors = {InvalidNewTransaction: b'INVALID_NEW_TX'}


class NodeIpcServer(amp.AMP):
    __slots__ = ('vertex_parser', 'vertex_handler')

    def __init__(self, *, vertex_parser: VertexParser, vertex_handler: VertexHandler) -> None:
        super().__init__()
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler

    @OnNewVertex.responder
    def on_new_vertex(self, vertex_bytes: bytes, fails_silently: bool) -> dict[str, Any]:
        vertex = self.vertex_parser.deserialize(vertex_bytes)
        success = self.vertex_handler.on_new_vertex(vertex, fails_silently=fails_silently)
        return dict(success=success)


class NodeIpcServerFactor(ServerFactory):
    __slots__ = ('vertex_parser', 'vertex_handler')

    def __init__(self, *, vertex_parser: VertexParser, vertex_handler: VertexHandler) -> None:
        super().__init__()
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler

    def buildProtocol(self, addr: IAddress) -> NodeIpcServer:
        p = NodeIpcServer(vertex_parser=self.vertex_parser, vertex_handler=self.vertex_handler)
        p.factory = self
        return p
