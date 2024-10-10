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

from hathor.p2p.p2p_dependencies import P2PDependencies
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_v2.agent import NodeBlockSync

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV2Factory(SyncAgentFactory):
    def __init__(self, dependencies: P2PDependencies) -> None:
        self.dependencies = dependencies

    def create_sync_agent(self, protocol: 'HathorProtocol') -> SyncAgent:
        return NodeBlockSync(
            protocol=protocol,
            dependencies=self.dependencies,
        )
