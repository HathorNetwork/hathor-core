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

from abc import abstractmethod
from typing import Protocol

from hathor.p2p.factory import HathorClientFactory, HathorServerFactory
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.sync_version import SyncVersion
from hathor.transaction import BaseTransaction


class P2PManagerProtocol(Protocol):
    @abstractmethod
    async def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_connections(self) -> set[HathorProtocol]:
        raise NotImplementedError

    @abstractmethod
    def get_server_factory(self) -> HathorServerFactory:
        raise NotImplementedError

    @abstractmethod
    def get_client_factory(self) -> HathorClientFactory:
        raise NotImplementedError

    @abstractmethod
    def enable_localhost_only(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def has_synced_peer(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def reload_entrypoints_and_connections(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def enable_sync_version(self, sync_version: SyncVersion) -> None:
        raise NotImplementedError

    @abstractmethod
    def add_peer_discovery(self, peer_discovery: PeerDiscovery) -> None:
        raise NotImplementedError

    @abstractmethod
    def add_listen_address_description(self, addr: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def disconnect_all_peers(self, *, force: bool = False) -> None:
        raise NotImplementedError
