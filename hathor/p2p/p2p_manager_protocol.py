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
from typing import Iterator, Protocol

from hathor.p2p.protocol import ConnectionMetrics
from hathor.transaction import BaseTransaction


class P2PManagerProtocol(Protocol):
    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def set_localhost_only(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def has_synced_peer(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_all_connection_metrics(self) -> Iterator[tuple[str, str, ConnectionMetrics]]:
        raise NotImplementedError

    @abstractmethod
    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def reload_entrypoints_and_connections(self) -> None:
        raise NotImplementedError
