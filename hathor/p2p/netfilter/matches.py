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

from abc import ABC, abstractmethod
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hathor.p2p.netfilter.context import NetfilterContext


class NetfilterMatch(ABC):
    """Abstract match class."""

    def to_json(self) -> dict[str, Any]:
        return {
            'type': type(self).__name__,
            'match_params': {}
        }

    @abstractmethod
    def match(self, context: 'NetfilterContext') -> bool:
        raise NotImplementedError


class NetfilterMatchAll(NetfilterMatch):
    """Always match."""
    def match(self, context: 'NetfilterContext') -> bool:
        return True


class TwoVariablesMatch(NetfilterMatch):
    def __init__(self, a: NetfilterMatch, b: NetfilterMatch):
        self.a = a
        self.b = b

    def to_json(self) -> dict[str, Any]:
        data = super().to_json()
        data['match_params']['a'] = self.a.to_json()
        data['match_params']['b'] = self.b.to_json()
        return data


class NetfilterMatchAnd(TwoVariablesMatch):
    """Logic AND operation for two matches. When the first fails, the second is not executed."""

    def match(self, context: 'NetfilterContext') -> bool:
        if not self.a.match(context):
            return False
        if not self.b.match(context):
            return False
        return True


class NetfilterMatchOr(TwoVariablesMatch):
    """Logic OR operation for two matches. When the first matches, the second is not executed."""

    def match(self, context: 'NetfilterContext') -> bool:
        if self.a.match(context):
            return True
        if self.b.match(context):
            return True
        return False


class NetfilterMatchIPAddress(NetfilterMatch):
    """Match an IP address or network."""
    def __init__(self, host: str):
        """`host` can be either an ip address or a network.

        Examples:
            127.0.0.1
            192.168.0.8
            192.168.0.0/24
            0.0.0.0/0 (match all addresses)
        """
        self.network = ip_network(host)

    def to_json(self) -> dict[str, Any]:
        data = super().to_json()
        data['match_params']['host'] = str(self.network)
        return data

    def match(self, context: 'NetfilterContext') -> bool:
        if context.addr is None:
            return False

        if not hasattr(context.addr, 'host'):
            return False

        try:
            host = ip_address(getattr(context.addr, 'host'))
        except ValueError:
            return False

        if self.network.version != host.version:
            return False

        if host not in self.network:
            return False

        return True


class NetfilterMatchPeerId(NetfilterMatch):
    """Match a Peer-ID."""
    def __init__(self, peer_id: str):
        self.peer_id = peer_id

    def to_json(self) -> dict[str, Any]:
        data = super().to_json()
        data['match_params']['peer_id'] = self.peer_id
        return data

    def match(self, context: 'NetfilterContext') -> bool:
        if context.protocol is None:
            return False

        if context.protocol._peer is None:
            return False

        if str(context.protocol.peer.id) != self.peer_id:
            return False

        return True
