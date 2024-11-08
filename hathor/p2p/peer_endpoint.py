# Copyright 2024 Hathor Labs
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

from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlparse

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.interfaces import IAddress, IStreamClientEndpoint
from typing_extensions import Self

from hathor.p2p.peer_id import PeerId
from hathor.reactor import ReactorProtocol as Reactor

COMPARISON_ERROR_MESSAGE = (
    'never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! '
    'instead, compare the addr attribute explicitly, and if relevant, the peer_id too.'
)


class Protocol(Enum):
    TCP = 'tcp'


@dataclass(frozen=True, slots=True)
class PeerAddress:
    """Peer address as received when a connection is made."""

    protocol: Protocol
    host: str
    port: int

    def __str__(self) -> str:
        return f'{self.protocol.value}://{self.host}:{self.port}'

    def __eq__(self, other: Any) -> bool:
        """
        This function implements strict comparison between two PeerAddress insteances. Comparison between a PeerAddress
        and a PeerEndpoint, or between two PeerEndpoint instances, purposefully throws a ValueError.

        Instead, in those cases users should explicity compare the underlying PeerAddress instances using the `addr`
        attribute. This ensures we don't have issues with implicit equality checks,such as when using the `in` operator

        Examples:

        >>> ep1 = 'tcp://foo:111'
        >>> ep2 = 'tcp://foo:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep3 = 'tcp://foo:111/?id=bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> ep4 = 'tcp://bar:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep5 = 'tcp://foo:112/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep6 = 'tcp://localhost:111'
        >>> ep7 = 'tcp://127.0.0.1:111'
        >>> PeerEndpoint.parse(ep1).addr == PeerEndpoint.parse(ep2).addr
        True
        >>> PeerEndpoint.parse(ep2).addr == PeerEndpoint.parse(ep3).addr
        True
        >>> PeerEndpoint.parse(ep1).addr == PeerEndpoint.parse(ep4).addr
        False
        >>> PeerEndpoint.parse(ep2).addr == PeerEndpoint.parse(ep4).addr
        False
        >>> PeerEndpoint.parse(ep2).addr == PeerEndpoint.parse(ep5).addr
        False
        >>> PeerEndpoint.parse(ep6).addr == PeerEndpoint.parse(ep7).addr
        True
        >>> PeerEndpoint.parse(ep1) == PeerEndpoint.parse(ep1)
        Traceback (most recent call last):
        ...
        ValueError: never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! \
instead, compare the addr attribute explicitly, and if relevant, the peer_id too.
        >>> PeerEndpoint.parse(ep1) == PeerEndpoint.parse(ep1).addr
        Traceback (most recent call last):
        ...
        ValueError: never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! \
instead, compare the addr attribute explicitly, and if relevant, the peer_id too.
        >>> PeerEndpoint.parse(ep1).addr == PeerEndpoint.parse(ep1)
        Traceback (most recent call last):
        ...
        ValueError: never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! \
instead, compare the addr attribute explicitly, and if relevant, the peer_id too.
        >>> PeerEndpoint.parse(ep1) != PeerEndpoint.parse(ep4).addr
        Traceback (most recent call last):
        ...
        ValueError: never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! \
instead, compare the addr attribute explicitly, and if relevant, the peer_id too.
        >>> PeerEndpoint.parse(ep1) in [PeerEndpoint.parse(ep1)]
        Traceback (most recent call last):
        ...
        ValueError: never compare PeerAddress with PeerEndpoint or two PeerEndpoint instances directly! \
instead, compare the addr attribute explicitly, and if relevant, the peer_id too.
        >>> PeerEndpoint.parse(ep1).addr in [PeerEndpoint.parse(ep1).addr]
        True
        >>> PeerEndpoint.parse(ep1).addr != PeerEndpoint.parse(ep4).addr
        True
        """
        if not isinstance(other, PeerAddress):
            raise ValueError(COMPARISON_ERROR_MESSAGE)

        if self.is_localhost() and other.is_localhost():
            return (self.protocol, self.port) == (other.protocol, other.port)

        return (self.protocol, self.host, self.port) == (other.protocol, other.host, other.port)

    def __ne__(self, other: Any) -> bool:
        return not self == other

    @classmethod
    def parse(cls, description: str) -> Self:
        protocol, host, port, query = _parse_address_parts(description)
        if query:
            raise ValueError(f'unexpected query: "{description}". did you incorrectly add an id=?')
        return cls(protocol, host, port)

    @classmethod
    def from_hostname_address(cls, hostname: str, address: IPv4Address | IPv6Address) -> Self:
        return cls.parse(f'{address.type}://{hostname}:{address.port}')

    @classmethod
    def from_address(cls, address: IAddress) -> Self:
        """Create a PeerAddress from a Twisted IAddress."""
        if not isinstance(address, (IPv4Address, IPv6Address)):
            raise NotImplementedError(f'address: {address}')
        return cls.parse(f'{address.type}://{address.host}:{address.port}')

    def to_client_endpoint(self, reactor: Reactor) -> IStreamClientEndpoint:
        """This method generates a twisted client endpoint that has a .connect() method."""
        # XXX: currently we don't support IPv6, but when we do we have to decide between TCP4ClientEndpoint and
        # TCP6ClientEndpoint, when the host is an IP address that is easy, but when it is a DNS hostname, we will not
        # know which to use until we know which resource records it holds (A or AAAA)
        return TCP4ClientEndpoint(reactor, self.host, self.port)

    def is_localhost(self) -> bool:
        """Used to determine if the address host is a localhost address.

        Examples:

        >>> PeerAddress.parse('tcp://127.0.0.1:444').is_localhost()
        True
        >>> PeerAddress.parse('tcp://localhost:444').is_localhost()
        True
        >>> PeerAddress.parse('tcp://8.8.8.8:444').is_localhost()
        False
        >>> PeerAddress.parse('tcp://foo.bar:444').is_localhost()
        False
        """
        return self.host in ('127.0.0.1', 'localhost')

    def with_id(self, peer_id: PeerId | None = None) -> PeerEndpoint:
        """Create a PeerEndpoint instance with self as the address and with the provided peer_id, or None."""
        return PeerEndpoint(self, peer_id)


@dataclass(frozen=True, slots=True)
class PeerEndpoint:
    """Peer endpoint description (returned from DNS query, or received from the p2p network) may contain a peer-id."""

    addr: PeerAddress
    peer_id: PeerId | None = None

    def __str__(self) -> str:
        return str(self.addr) if self.peer_id is None else f'{self.addr}/?id={self.peer_id}'

    def __eq__(self, other: Any) -> bool:
        """See PeerAddress.__eq__"""
        raise ValueError(COMPARISON_ERROR_MESSAGE)

    def __ne__(self, other: Any) -> bool:
        """See PeerAddress.__eq__"""
        raise ValueError(COMPARISON_ERROR_MESSAGE)

    @classmethod
    def parse(cls, description: str) -> PeerEndpoint:
        """Parse endpoint description into an PeerEndpoint object.

        Examples:

        >>> str(PeerEndpoint.parse('tcp://127.0.0.1:40403/'))
        'tcp://127.0.0.1:40403'

        >>> id1 = 'c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> PeerEndpoint.parse(f'tcp://127.0.0.1:40403/?id={id1}')
        PeerEndpoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), \
peer_id=PeerId('c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'))

        >>> str(PeerEndpoint.parse(f'tcp://127.0.0.1:40403/?id={id1}'))
        'tcp://127.0.0.1:40403/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'

        >>> PeerEndpoint.parse('tcp://127.0.0.1:40403')
        PeerEndpoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), peer_id=None)

        >>> PeerEndpoint.parse('tcp://127.0.0.1:40403/')
        PeerEndpoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), peer_id=None)

        >>> PeerEndpoint.parse('tcp://foo.bar.baz:40403/')
        PeerEndpoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='foo.bar.baz', port=40403), \
peer_id=None)

        >>> str(PeerEndpoint.parse('tcp://foo.bar.baz:40403/'))
        'tcp://foo.bar.baz:40403'

        >>> PeerEndpoint.parse('tcp://127.0.0.1:40403/?id=123')
        Traceback (most recent call last):
        ...
        ValueError: non-hexadecimal number found in fromhex() arg at position 3

        >>> PeerEndpoint.parse('tcp://127.0.0.1:4040f')
        Traceback (most recent call last):
        ...
        ValueError: Port could not be cast to integer value as '4040f'

        >>> PeerEndpoint.parse('udp://127.0.0.1:40403/')
        Traceback (most recent call last):
        ...
        ValueError: 'udp' is not a valid Protocol

        >>> PeerEndpoint.parse('tcp://127.0.0.1/')
        Traceback (most recent call last):
        ...
        ValueError: expected a port: "tcp://127.0.0.1/"

        >>> PeerEndpoint.parse('tcp://:40403/')
        Traceback (most recent call last):
        ...
        ValueError: expected a host: "tcp://:40403/"

        >>> PeerEndpoint.parse('tcp://127.0.0.1:40403/foo')
        Traceback (most recent call last):
        ...
        ValueError: unexpected path: "tcp://127.0.0.1:40403/foo"

        >>> id2 = 'bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> PeerEndpoint.parse(f'tcp://127.0.0.1:40403/?id={id1}&id={id2}')
        Traceback (most recent call last):
        ...
        ValueError: unexpected id count: 2
        """
        protocol, host, port, query_str = _parse_address_parts(description)
        peer_id: PeerId | None = None

        if query_str:
            query = parse_qs(query_str)
            if 'id' in query:
                ids = query['id']
                if len(ids) != 1:
                    raise ValueError(f'unexpected id count: {len(ids)}')
                peer_id = PeerId(ids[0])

        return PeerAddress(protocol, host, port).with_id(peer_id)


def _parse_address_parts(description: str) -> tuple[Protocol, str, int, str]:
    url = urlparse(description)
    protocol = Protocol(url.scheme)
    host = url.hostname
    if host is None:
        raise ValueError(f'expected a host: "{description}"')
    port = url.port
    if port is None:
        raise ValueError(f'expected a port: "{description}"')
    if url.path not in {'', '/'}:
        raise ValueError(f'unexpected path: "{description}"')

    return protocol, host, port, url.query
