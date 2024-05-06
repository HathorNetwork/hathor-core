# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.p2p.sync_v2.p2p_storage import AsyncP2PStorage, P2PStorage
from hathor.p2p.sync_v2.p2p_vertex_handler import AsyncP2PVertexHandler, P2PVertexHandler
from hathor.reactor import ReactorProtocol as Reactor

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV2Factory(SyncAgentFactory):
    def __init__(self, connections: ConnectionsManager, *, use_async: bool = True) -> None:
        self.connections = connections
        self._use_async = use_async

    def create_sync_agent(self, protocol: 'HathorProtocol', reactor: Reactor) -> SyncAgent:
        if not self._use_async:
            p2p_storage = P2PStorage(protocol=protocol, tx_storage=protocol.node.tx_storage)
            p2p_vertex_handler = P2PVertexHandler(manager=protocol.node)
        else:
            p2p_storage = AsyncP2PStorage(protocol=protocol, tx_storage=protocol.node.tx_storage)
            p2p_vertex_handler = AsyncP2PVertexHandler(
                manager=protocol.node,
                p2p_storage=p2p_storage,
            )

        return NodeBlockSync(
            protocol=protocol,
            reactor=reactor,
            p2p_storage=p2p_storage,
            p2p_vertex_handler=p2p_vertex_handler,
        )
