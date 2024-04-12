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

from collections import deque
from typing import NamedTuple

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from typing_extensions import override

from hathor.manager import HathorManager
from hathor.p2p.sync_v2.p2p_storage import AsyncP2PStorage
from hathor.transaction import BaseTransaction


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
    __slots__ = ('_reactor', '_p2p_storage', '_new_vertex_queue')

    def __init__(self, *, manager: HathorManager, p2p_storage: AsyncP2PStorage) -> None:
        super().__init__(manager=manager)
        self._reactor = manager.reactor
        self._p2p_storage = p2p_storage
        self._new_vertex_queue: deque[_NewVertex] = deque()

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
        deferred: Deferred[bool] = Deferred()
        self._new_vertex_queue.append(_NewVertex(vertex, fails_silently, propagate_to_peers, deferred))
        self._p2p_storage.add_new_vertex(vertex, deferred)
        if len(self._new_vertex_queue) == 1:
            self._reactor.callLater(0, self._process_queue)
        return deferred

    def _process_queue(self) -> None:
        """Process the new vertex queue. It calls itself recursively until the queue is empty."""
        if len(self._new_vertex_queue) == 0:
            return

        new_vertex = self._new_vertex_queue.popleft()

        try:
            result = self._manager.on_new_tx(
                new_vertex.vertex,
                fails_silently=new_vertex.fails_silently,
                propagate_to_peers=new_vertex.propagate_to_peers,
            )
        except Exception as e:
            result = Failure(e)

        new_vertex.deferred.callback(result)
        self._reactor.callLater(0, self._process_queue)
