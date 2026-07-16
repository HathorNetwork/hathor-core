# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Optional

from twisted.internet.interfaces import IAddress, IProtocolFactory
from twisted.internet.protocol import Protocol
from twisted.protocols.policies import WrappingFactory

from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.context import NetfilterContext

if TYPE_CHECKING:
    from hathor.p2p.manager import ConnectionsManager


class NetfilterFactory(WrappingFactory):
    """Wrapper factory to easily check new connections."""
    def __init__(self, connections: 'ConnectionsManager', wrappedFactory: 'IProtocolFactory'):
        super().__init__(wrappedFactory)
        self.connections = connections

    def buildProtocol(self, addr: IAddress) -> Optional[Protocol]:
        context = NetfilterContext(
            connections=self.connections,
            addr=addr,
        )
        verdict = get_table('filter').get_chain('pre_conn').process(context)
        if not bool(verdict):
            return None
        return super().buildProtocol(addr)
