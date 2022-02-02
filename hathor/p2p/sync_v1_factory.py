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

from hathor.p2p.downloader import Downloader
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.node_sync import NodeSyncTimestamp
from hathor.p2p.sync_factory import SyncManagerFactory
from hathor.p2p.sync_manager import SyncManager
from hathor.util import Reactor

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV1Factory(SyncManagerFactory):
    def __init__(self, connections: ConnectionsManager):
        self.downloader = Downloader(connections.manager)

    def create_sync_manager(self, protocol: 'HathorProtocol', reactor: Optional[Reactor] = None) -> SyncManager:
        return NodeSyncTimestamp(protocol, downloader=self.downloader, reactor=reactor)
