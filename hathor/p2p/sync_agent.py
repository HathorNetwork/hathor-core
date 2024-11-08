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

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable

from typing_extensions import assert_never

from hathor.p2p import P2PDependencies
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.sync_version import SyncVersion
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncAgent(ABC):
    @classmethod
    def create(
        cls,
        *,
        sync_version: SyncVersion,
        protocol: HathorProtocol,
        dependencies: P2PDependencies,
    ) -> SyncAgent:
        match sync_version:
            case SyncVersion.V1_1:
                from hathor.p2p.manager import ConnectionsManager
                from hathor.p2p.sync_v1.agent import NodeSyncTimestamp
                assert isinstance(protocol.p2p_manager, ConnectionsManager)
                downloader = protocol.p2p_manager.get_sync_v1_downloader()
                return NodeSyncTimestamp(protocol=protocol, dependencies=dependencies, downloader=downloader)
            case SyncVersion.V2:
                from hathor.p2p.sync_v2.agent import NodeBlockSync
                return NodeBlockSync(protocol=protocol, dependencies=dependencies)
            case _:
                assert_never(sync_version)

    @abstractmethod
    def is_started(self) -> bool:
        """Whether the manager started running"""
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        """Start running this manager"""
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Stop running this manager"""
        raise NotImplementedError

    @abstractmethod
    def get_cmd_dict(self) -> dict[ProtocolMessages, Callable[[str], None]]:
        """Command dict to add to the protocol handler"""
        raise NotImplementedError

    @abstractmethod
    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        """Propagate a transaction to the connected peer"""
        raise NotImplementedError

    @abstractmethod
    def is_synced(self) -> bool:
        """Whether we are synced with the other peer (if we are ahead it should still be True)"""
        raise NotImplementedError

    @abstractmethod
    def is_errored(self) -> bool:
        """Whether the manager entered an error state"""
        raise NotImplementedError

    @abstractmethod
    def is_sync_enabled(self) -> bool:
        """Return true if the sync is enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_sync(self) -> None:
        """Enable sync."""
        raise NotImplementedError

    @abstractmethod
    def disable_sync(self) -> None:
        """Disable sync."""
        raise NotImplementedError
