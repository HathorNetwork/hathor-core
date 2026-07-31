# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.builder import BuildArtifacts
from hathor.sysctl import (
    ConnectionsManagerSysctl,
    FeatureActivationSysctl,
    HathorManagerSysctl,
    MiningManagerSysctl,
    Sysctl,
    WebsocketManagerSysctl,
)
from hathor.sysctl.storage import StorageSysctl


class SysctlBuilder:
    """Builder for the sysctl tree."""

    def __init__(self, artifacts: BuildArtifacts) -> None:
        self.artifacts = artifacts

    def build(self) -> Sysctl:
        """Build the sysctl tree."""
        root = Sysctl()

        core = HathorManagerSysctl(self.artifacts.manager)
        core.put_child('features', FeatureActivationSysctl(self.artifacts.bit_signaling_service))
        core.put_child('mining', MiningManagerSysctl(self.artifacts.manager))

        root.put_child('core', core)
        root.put_child('p2p', ConnectionsManagerSysctl(self.artifacts.p2p_manager))
        root.put_child('storage', StorageSysctl(self.artifacts.rocksdb_storage))

        ws_factory = self.artifacts.manager.websocket_factory
        if ws_factory is not None:
            root.put_child('ws', WebsocketManagerSysctl(ws_factory))

        return root
