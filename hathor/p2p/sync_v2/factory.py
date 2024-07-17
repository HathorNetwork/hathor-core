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

from hathor.conf.settings import HathorSettings
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction.vertex_parser import VertexParser

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV2Factory(SyncAgentFactory):
    def __init__(self, settings: HathorSettings, connections: ConnectionsManager, *, vertex_parser: VertexParser):
        self._settings = settings
        self.connections = connections
        self.vertex_parser = vertex_parser

    def create_sync_agent(self, protocol: 'HathorProtocol', reactor: Reactor) -> SyncAgent:
        return NodeBlockSync(self._settings, protocol, reactor=reactor, vertex_parser=self.vertex_parser)
