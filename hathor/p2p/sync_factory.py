# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from hathor.p2p.sync_agent import SyncAgent
from hathor.reactor import ReactorProtocol as Reactor

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncAgentFactory(ABC):
    @abstractmethod
    def create_sync_agent(self, protocol: 'HathorProtocol', reactor: Reactor) -> SyncAgent:
        pass
