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

from abc import ABC, abstractmethod

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states.base import CommandHandler
from hathor.transaction import BaseTransaction


class SyncAgent(ABC):
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
    def get_cmd_dict(self) -> dict[ProtocolMessages, CommandHandler]:
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
