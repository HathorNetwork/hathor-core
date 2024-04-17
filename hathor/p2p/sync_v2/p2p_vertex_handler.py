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

from typing import NamedTuple

from structlog import get_logger
from twisted.internet import defer
from twisted.internet.defer import Deferred
from typing_extensions import override

from hathor.exception import HathorError
from hathor.manager import HathorManager
from hathor.p2p.sync_v2.p2p_storage import AsyncP2PStorage
from hathor.transaction import BaseTransaction

logger = get_logger()


class _NewVertex(NamedTuple):
    vertex: BaseTransaction
    fails_silently: bool
    propagate_to_peers: bool
    deferred: Deferred[bool]


class P2PVertexHandler:
    """
    This class represents a single point of contact for sync-v2 handling of new vertices.
    Every time a new vertex is received by sync-v2, it should call `handle_new_vertex()` to send the vertex to the rest
    of the pipeline (i.e. verification, consensus, saving, propagation, etc).
    This class handles vertices synchronously.
    """
    __slots__ = ('_manager',)

    def __init__(self, *, manager: HathorManager) -> None:
        self._manager = manager

    def handle_new_vertex(
        self,
        vertex: BaseTransaction,
        *,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
    ) -> Deferred[bool]:
        """Synchronously handle a new vertex and return a Deferred that will always be completed."""
        assert vertex.storage is None
        try:
            result = self._manager.on_new_tx(
                vertex,
                fails_silently=fails_silently,
                propagate_to_peers=propagate_to_peers,
            )
            return defer.succeed(result)
        except Exception as e:
            return defer.fail(e)


class AsyncP2PVertexHandler(P2PVertexHandler):
    """
    This class represents a single point of contact for sync-v2 handling of new vertices. Every time a new vertex is
    received by sync-v2, it should call `handle_new_vertex()` to send the vertex to the rest of the pipeline
    (i.e. verification, consensus, saving, propagation, etc). This class handles vertices asynchronously.
    """
    __slots__ = ('_log', '_reactor', '_p2p_storage', '_vertex_count')

    def __init__(self, *, manager: HathorManager, p2p_storage: AsyncP2PStorage) -> None:
        super().__init__(manager=manager)
        self._log = logger.new()
        self._reactor = manager.reactor
        self._p2p_storage = p2p_storage
        self._vertex_count: int = 0

    @override
    def handle_new_vertex(
        self,
        vertex: BaseTransaction,
        *,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
    ) -> Deferred[bool]:
        """Asynchronously handle a new vertex, i.e., it returns without blocking for handling and returns a
        Deferred that will fire when the handling is complete."""
        coro = self._handle_new_vertex(vertex, fails_silently=fails_silently, propagate_to_peers=propagate_to_peers)
        return Deferred.fromCoroutine(coro)

    async def _handle_new_vertex(
        self,
        vertex: BaseTransaction,
        *,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
    ) -> bool:
        self._vertex_count += 1
        self._p2p_storage.add_new_vertex(vertex)
        current_count = self._vertex_count
        result = False
        self._log.info(f'received vertex {current_count}', hash=vertex.hash_hex, handler=self)

        try:
            result = await self._manager.vertex_handler.on_new_vertex_async(
                vertex,
                fails_silently=fails_silently,
                propagate_to_peers=propagate_to_peers,
            )
        except Exception as e:  # TODO: Maybe this block can be removed
            if not isinstance(e, HathorError):
                self._log.error('unhandled exception in vertex completion', exception=str(e), exc_info=True)
            raise
        finally:
            self._p2p_storage.complete_vertex(vertex, result)
            self._log.info(f'completed vertex {current_count}/{self._vertex_count}', hash=vertex.hash_hex)

        return result
