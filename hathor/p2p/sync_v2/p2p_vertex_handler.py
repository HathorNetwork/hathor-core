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

from hathor.manager import HathorManager
from hathor.transaction import BaseTransaction


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
    ) -> bool:
        return self._manager.on_new_tx(
            vertex,
            fails_silently=fails_silently,
            propagate_to_peers=propagate_to_peers,
            is_sync_v2=True
        )
