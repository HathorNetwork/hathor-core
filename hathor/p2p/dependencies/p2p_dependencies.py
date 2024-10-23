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

from hathor.conf.settings import HathorSettings
from hathor.p2p.dependencies.protocols import (
    P2PTransactionStorageProtocol,
    P2PVerificationServiceProtocol,
    P2PVertexHandlerProtocol,
)
from hathor.reactor import ReactorProtocol
from hathor.transaction.vertex_parser import VertexParser


class P2PDependencies:
    """A simple class to unify all node dependencies that are required by P2P."""

    __slots__ = (
        'reactor',
        'settings',
        'vertex_parser',
        'vertex_handler',
        'verification_service',
        'tx_storage',
        'capabilities',
        'whitelist_only',
        '_has_sync_version_capability',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        vertex_parser: VertexParser,
        vertex_handler: P2PVertexHandlerProtocol,
        verification_service: P2PVerificationServiceProtocol,
        tx_storage: P2PTransactionStorageProtocol,
        capabilities: list[str],
        whitelist_only: bool,
    ) -> None:
        self.reactor = reactor
        self.settings = settings
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler
        self.verification_service = verification_service
        self.tx_storage = tx_storage

        # List of capabilities of the peer
        self.capabilities = capabilities

        # Parameter to explicitly enable whitelist-only mode, when False it will still check the whitelist for sync-v1
        self.whitelist_only = whitelist_only

        self._has_sync_version_capability = settings.CAPABILITY_SYNC_VERSION in capabilities

    def has_sync_version_capability(self) -> bool:
        return self._has_sync_version_capability
