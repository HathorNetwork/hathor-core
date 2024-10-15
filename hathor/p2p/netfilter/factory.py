# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Optional

from twisted.internet.interfaces import IAddress, IProtocolFactory
from twisted.internet.protocol import Protocol
from twisted.protocols.policies import WrappingFactory

from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.context import NetfilterContext

if TYPE_CHECKING:
    from hathor.p2p.p2p_manager import P2PManager


class NetfilterFactory(WrappingFactory):
    """Wrapper factory to easily check new connections."""
    def __init__(self, connections: 'P2PManager', wrappedFactory: 'IProtocolFactory'):
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
