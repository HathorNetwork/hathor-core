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

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterable, Protocol

from hathor.indexes.height_index import HeightInfo
from hathor.transaction import BaseTransaction, Block, Vertex
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.p2p.entrypoint import Entrypoint
    from hathor.p2p.peer import PublicPeer
    from hathor.p2p.peer_id import PeerId
    from hathor.p2p.protocol import ConnectionMetrics
    from hathor.p2p.sync_factory import SyncAgentFactory
    from hathor.p2p.sync_version import SyncVersion


class P2PConnectionProtocol(Protocol):
    """Abstract HathorProtocol as a Python protocol to be used in P2PManager."""

    def is_synced(self) -> bool: ...
    def send_tx_to_peer(self, tx: BaseTransaction) -> None: ...
    def disconnect(self, reason: str = '', *, force: bool = False) -> None: ...
    def get_peer(self) -> PublicPeer: ...
    def get_peer_if_set(self) -> PublicPeer | None: ...
    def get_entrypoint(self) -> Entrypoint | None: ...
    def enable_sync(self) -> None: ...
    def disable_sync(self) -> None: ...
    def is_sync_enabled(self) -> bool: ...
    def send_peers(self, peers: Iterable[PublicPeer]) -> None: ...
    def is_inbound(self) -> bool: ...
    def send_error_and_close_connection(self, msg: str) -> None: ...
    def get_metrics(self) -> ConnectionMetrics: ...


class P2PManagerProtocol(Protocol):
    """Abstract the P2PManager as a Python protocol to be used in P2P classes."""

    def is_peer_whitelisted(self, peer_id: PeerId) -> bool: ...
    def get_enabled_sync_versions(self) -> set[SyncVersion]: ...
    def get_sync_factory(self, sync_version: SyncVersion) -> SyncAgentFactory: ...
    def get_verified_peers(self) -> Iterable[PublicPeer]: ...
    def on_receive_peer(self, peer: dict[str, Any]) -> None: ...
    def on_peer_connect(self, addr: str) -> None: ...
    def on_peer_ready(self, addr: str) -> None: ...
    def on_peer_disconnect(self, addr: str) -> None: ...
    def get_randbytes(self, n: int) -> bytes: ...
    def is_peer_connected(self, peer_id: PeerId) -> bool: ...
    def send_tx_to_peers(self, tx: BaseTransaction) -> None: ...


class P2PVertexHandlerProtocol(Protocol):
    """Abstract the VertexHandler as a Python protocol to be used in P2P classes."""

    def on_new_vertex(self, vertex: Vertex, *, fails_silently: bool = True) -> bool: ...


class P2PVerificationServiceProtocol(Protocol):
    """Abstract the VerificationService as a Python protocol to be used in P2P classes."""

    def verify_basic(self, vertex: Vertex) -> None: ...


class P2PTransactionStorageProtocol(Protocol):
    """Abstract the TransactionStorage as a Python protocol to be used in P2P classes."""

    def get_vertex(self, vertex_id: VertexId) -> Vertex: ...
    def get_block(self, block_id: VertexId) -> Block: ...
    def transaction_exists(self, vertex_id: VertexId) -> bool: ...
    def can_validate_full(self, vertex: Vertex) -> bool: ...
    def compare_bytes_with_local_tx(self, vertex: Vertex) -> bool: ...
    def get_best_block(self) -> Block: ...
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]: ...
    def get_mempool_tips(self) -> set[VertexId]: ...
    def get_block_id_by_height(self, height: int) -> VertexId | None: ...
    def partial_vertex_exists(self, vertex_id: VertexId) -> bool: ...
