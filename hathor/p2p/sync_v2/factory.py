# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING

from hathor.conf.settings import HathorSettings
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_v2.agent import NodeBlockSync
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction.vertex_parser import VertexParser
from hathor.vertex_handler import VertexHandler

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class SyncV2Factory(SyncAgentFactory):
    def __init__(
        self,
        settings: HathorSettings,
        connections: ConnectionsManager,
        *,
        vertex_parser: VertexParser,
        vertex_handler: VertexHandler,
    ):
        self._settings = settings
        self.connections = connections
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler

    def create_sync_agent(self, protocol: 'HathorProtocol', reactor: Reactor) -> SyncAgent:
        return NodeBlockSync(
            self._settings,
            protocol,
            reactor=reactor,
            vertex_parser=self.vertex_parser,
            vertex_handler=self.vertex_handler,
        )
