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

from typing import Iterable

from hathor.p2p.dependencies.protocols import P2PConnectionProtocol
from hathor.p2p.peer import PublicPeer, UnverifiedPeer
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_version import SyncVersion
from hathor.transaction import BaseTransaction


class RemoteP2PManager:
    def is_peer_whitelisted(self, peer_id: PeerId) -> bool:
        raise NotImplementedError

    def get_enabled_sync_versions(self) -> set[SyncVersion]:
        raise NotImplementedError

    def get_sync_factory(self, sync_version: SyncVersion) -> SyncAgentFactory:
        raise NotImplementedError

    def get_verified_peers(self) -> Iterable[PublicPeer]:
        raise NotImplementedError

    def on_receive_peer(self, peer: UnverifiedPeer) -> None:
        raise NotImplementedError

    def on_peer_connect(self, protocol: P2PConnectionProtocol) -> None:
        raise NotImplementedError

    def on_peer_ready(self, protocol: P2PConnectionProtocol) -> None:
        raise NotImplementedError

    def on_peer_disconnect(self, protocol: P2PConnectionProtocol) -> None:
        raise NotImplementedError

    def get_randbytes(self, n: int) -> bytes:
        raise NotImplementedError

    def is_peer_connected(self, peer_id: PeerId) -> bool:
        raise NotImplementedError

    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        raise NotImplementedError
