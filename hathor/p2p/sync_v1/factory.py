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

from typing import TYPE_CHECKING, Optional

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_v1.agent import NodeSyncTimestamp
from hathor.p2p.sync_v1.downloader import Downloader
from hathor.reactor import ReactorProtocol as Reactor

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV11Factory(SyncAgentFactory):
    def __init__(self, connections: ConnectionsManager):
        self.connections = connections
        self._downloader: Optional[Downloader] = None

    def get_downloader(self) -> Downloader:
        if self._downloader is None:
            assert self.connections.manager is not None
            self._downloader = Downloader(self.connections.manager)
        return self._downloader

    def create_sync_agent(self, protocol: 'HathorProtocol', reactor: Reactor) -> SyncAgent:
        return NodeSyncTimestamp(protocol, downloader=self.get_downloader(), reactor=reactor)
