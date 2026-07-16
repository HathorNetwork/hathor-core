# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from typing import Callable

from hathor.p2p.messages import ProtocolMessages
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
