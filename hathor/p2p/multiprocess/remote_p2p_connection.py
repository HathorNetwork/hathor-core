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

from hathor.p2p.entrypoint import Entrypoint
from hathor.p2p.peer import PublicPeer
from hathor.p2p.protocol import ConnectionMetrics
from hathor.transaction import BaseTransaction


class RemoteP2PConnection:
    __slots__ = ()

    def __init__(self, *, hosting_on: str) -> None:
        pass

    def is_synced(self) -> bool:
        raise NotImplementedError

    def send_tx_to_peer(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    def disconnect(self, reason: str = '', *, force: bool = False) -> None:
        raise NotImplementedError

    def get_peer(self) -> PublicPeer:
        raise NotImplementedError

    def get_peer_if_set(self) -> PublicPeer | None:
        raise NotImplementedError

    def get_entrypoint(self) -> Entrypoint | None:
        raise NotImplementedError

    def enable_sync(self) -> None:
        raise NotImplementedError

    def disable_sync(self) -> None:
        raise NotImplementedError

    def is_sync_enabled(self) -> bool:
        raise NotImplementedError

    def send_peers(self, peers: Iterable[PublicPeer]) -> None:
        raise NotImplementedError

    def is_inbound(self) -> bool:
        raise NotImplementedError

    def send_error_and_close_connection(self, msg: str) -> None:
        raise NotImplementedError

    def get_metrics(self) -> ConnectionMetrics:
        raise NotImplementedError
