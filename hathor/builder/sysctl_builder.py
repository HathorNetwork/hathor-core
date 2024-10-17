# Copyright 2023 Hathor Labs
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

from hathor.builder import BuildArtifacts
from hathor.p2p import P2PManager
from hathor.sysctl import (
    FeatureActivationSysctl,
    HathorManagerSysctl,
    P2PManagerSysctl,
    Sysctl,
    WebsocketManagerSysctl,
)


class SysctlBuilder:
    """Builder for the sysctl tree."""

    def __init__(self, artifacts: BuildArtifacts) -> None:
        self.artifacts = artifacts

    def build(self) -> Sysctl:
        """Build the sysctl tree."""
        root = Sysctl()

        core = HathorManagerSysctl(self.artifacts.manager)
        core.put_child('features', FeatureActivationSysctl(self.artifacts.bit_signaling_service))

        root.put_child('core', core)
        # assert isinstance(self.artifacts.p2p_manager, P2PManager), 'sysctl currently only supports P2PManager'
        # root.put_child('p2p', P2PManagerSysctl(self.artifacts.p2p_manager))

        ws_factory = self.artifacts.manager.websocket_factory
        if ws_factory is not None:
            root.put_child('ws', WebsocketManagerSysctl(ws_factory))

        return root
