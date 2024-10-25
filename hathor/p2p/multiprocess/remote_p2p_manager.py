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

from typing import Any, Iterable

import grpc

from hathor.p2p.peer import PublicPeer
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_version import SyncVersion
from hathor.transaction import BaseTransaction
from protos import p2p_pb2, p2p_pb2_grpc
from protos.p2p_pb2 import StringValue


class RemoteP2PManager:
    __slots__ = ('_channel', '_stub',)

    def __init__(self) -> None:
        self._channel = grpc.insecure_channel('localhost:50051')
        self._stub = p2p_pb2_grpc.P2PManagerStub(self._channel)

    # TODO: call this method
    def close(self) -> None:
        self._channel.close()

    def is_peer_whitelisted(self, peer_id: PeerId) -> bool:
        raise NotImplementedError

    def get_enabled_sync_versions(self) -> set[SyncVersion]:
        response: p2p_pb2.StringList = self._stub.GetEnabledSyncVersions(p2p_pb2.Empty())
        return {SyncVersion(version) for version in response.values}

    def get_sync_factory(self, sync_version: SyncVersion) -> SyncAgentFactory:
        raise NotImplementedError

    def get_verified_peers(self) -> Iterable[PublicPeer]:
        raise NotImplementedError

    def on_receive_peer(self, peer: dict[str, Any]) -> None:
        raise NotImplementedError

    def on_peer_connect(self, addr: str) -> None:
        self._stub.OnPeerConnect(StringValue(value=addr))

    def on_peer_ready(self, addr: str) -> None:
        self._stub.OnPeerReady(StringValue(value=addr))

    def on_peer_disconnect(self, addr: str) -> None:
        self._stub.OnPeerDisconnect(StringValue(value=addr))

    def get_randbytes(self, n: int) -> bytes:
        raise NotImplementedError

    def is_peer_connected(self, peer_id: PeerId) -> bool:
        raise NotImplementedError

    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        raise NotImplementedError
