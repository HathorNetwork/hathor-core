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
from urllib.parse import parse_qs, urlparse

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.interfaces import IAddress, IStreamClientEndpoint
from typing_extensions import Self

from hathor.p2p.peer_id import PeerId
from hathor.reactor import ReactorProtocol as Reactor


class Protocol(Enum):
    TCP = 'tcp'


@dataclass(frozen=True, slots=True)
class PeerAddress:
    """Peer address (received when a connection is made)."""

    protocol: Protocol
    host: str
    port: int

    def __str__(self) -> str:
        return f'{self.protocol.value}://{self.host}:{self.port}'

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, PeerAddress)
        if self.is_localhost() and other.is_localhost():
            return (self.protocol, self.port) == (other.protocol, other.port)
        return (self.protocol, self.host, self.port) == (other.protocol, other.host, other.port)

    @staticmethod
    def parse_parts(description: str) -> tuple[Protocol, str, int, str]:
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

    @classmethod
    def parse(cls, description: str) -> Self:
        protocol, host, port, query = cls.parse_parts(description)
        if query:
            raise ValueError(f'unexpected query: {description}')
        return cls(protocol, host, port)

    @classmethod
    def from_hostname_address(cls, hostname: str, address: IPv4Address | IPv6Address) -> Self:
        return cls.parse(f'{address.type}://{hostname}:{address.port}')

    @classmethod
    def from_address(cls, address: IAddress) -> Self:
        if not isinstance(address, (IPv4Address, IPv6Address)):
            raise NotImplementedError
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

    def into_entrypoint(self, peer_id: PeerId | None = None) -> Entrypoint:
        return Entrypoint(self, peer_id)


@dataclass(frozen=True, slots=True)
class Entrypoint:
    """Endpoint description (returned from DNS query, or received from the p2p network) may contain a peer-id."""
    addr: PeerAddress
    peer_id: PeerId | None = None

    def __str__(self) -> str:
        return str(self.addr) if self.peer_id is None else f'{self.addr}/?id={self.peer_id}'

    @classmethod
    def parse(cls, description: str) -> Entrypoint:
        """Parse endpoint description into an Entrypoint object.

        Examples:

        >>> str(Entrypoint.parse('tcp://127.0.0.1:40403/'))
        'tcp://127.0.0.1:40403'

        >>> id1 = 'c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}')
        Entrypoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), \
peer_id=PeerId('c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'))

        >>> str(Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}'))
        'tcp://127.0.0.1:40403/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'

        >>> Entrypoint.parse('tcp://127.0.0.1:40403')
        Entrypoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), peer_id=None)

        >>> Entrypoint.parse('tcp://127.0.0.1:40403/')
        Entrypoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403), peer_id=None)

        >>> Entrypoint.parse('tcp://foo.bar.baz:40403/')
        Entrypoint(addr=PeerAddress(protocol=<Protocol.TCP: 'tcp'>, host='foo.bar.baz', port=40403), peer_id=None)

        >>> str(Entrypoint.parse('tcp://foo.bar.baz:40403/'))
        'tcp://foo.bar.baz:40403'

        >>> Entrypoint.parse('tcp://127.0.0.1:40403/?id=123')
        Traceback (most recent call last):
        ...
        ValueError: non-hexadecimal number found in fromhex() arg at position 3

        >>> Entrypoint.parse('tcp://127.0.0.1:4040f')
        Traceback (most recent call last):
        ...
        ValueError: Port could not be cast to integer value as '4040f'

        >>> Entrypoint.parse('udp://127.0.0.1:40403/')
        Traceback (most recent call last):
        ...
        ValueError: 'udp' is not a valid Protocol

        >>> Entrypoint.parse('tcp://127.0.0.1/')
        Traceback (most recent call last):
        ...
        ValueError: expected a port: "tcp://127.0.0.1/"

        >>> Entrypoint.parse('tcp://:40403/')
        Traceback (most recent call last):
        ...
        ValueError: expected a host: "tcp://:40403/"

        >>> Entrypoint.parse('tcp://127.0.0.1:40403/foo')
        Traceback (most recent call last):
        ...
        ValueError: unexpected path: "tcp://127.0.0.1:40403/foo"

        >>> id2 = 'bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}&id={id2}')
        Traceback (most recent call last):
        ...
        ValueError: unexpected id count: 2
        """
        protocol, host, port, query_str = PeerAddress.parse_parts(description)
        peer_id: PeerId | None = None

        if query_str:
            query = parse_qs(query_str)
            if 'id' in query:
                ids = query['id']
                if len(ids) != 1:
                    raise ValueError(f'unexpected id count: {len(ids)}')
                peer_id = PeerId(ids[0])

        return PeerAddress(protocol, host, port).into_entrypoint(peer_id)

    def equals_ignore_peer_id(self, other: Self) -> bool:
        """Compares `self` and `other` ignoring the `peer_id` fields of either.

        Examples:

        >>> ep1 = 'tcp://foo:111'
        >>> ep2 = 'tcp://foo:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep3 = 'tcp://foo:111/?id=bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> ep4 = 'tcp://bar:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep5 = 'tcp://foo:112/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep6 = 'tcp://localhost:111'
        >>> ep7 = 'tcp://127.0.0.1:111'
        >>> Entrypoint.parse(ep1).equals_ignore_peer_id(Entrypoint.parse(ep2))
        True
        >>> Entrypoint.parse(ep2).equals_ignore_peer_id(Entrypoint.parse(ep3))
        True
        >>> Entrypoint.parse(ep1).equals_ignore_peer_id(Entrypoint.parse(ep4))
        False
        >>> Entrypoint.parse(ep2).equals_ignore_peer_id(Entrypoint.parse(ep4))
        False
        >>> Entrypoint.parse(ep2).equals_ignore_peer_id(Entrypoint.parse(ep5))
        False
        >>> Entrypoint.parse(ep6).equals_ignore_peer_id(Entrypoint.parse(ep7))
        True
        """
        return self.addr == other.addr

    def peer_id_conflicts_with(self, other: Self) -> bool:
        """Returns True if both self and other have a peer_id and they are different, returns False otherwise.

        This method ignores the host. Which is useful for catching the cases where both `self` and `other` have a
        declared `peer_id` and they are not equal.

        >>> desc_no_pid = 'tcp://127.0.0.1:40403/'
        >>> ep_no_pid = Entrypoint.parse(desc_no_pid)
        >>> desc_pid1 = 'tcp://127.0.0.1:40403/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep_pid1 = Entrypoint.parse(desc_pid1)
        >>> desc_pid2 = 'tcp://127.0.0.1:40403/?id=bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> ep_pid2 = Entrypoint.parse(desc_pid2)
        >>> desc2_pid2 = 'tcp://foo.bar:40403/?id=bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> ep2_pid2 = Entrypoint.parse(desc2_pid2)
        >>> ep_no_pid.peer_id_conflicts_with(ep_no_pid)
        False
        >>> ep_no_pid.peer_id_conflicts_with(ep_pid1)
        False
        >>> ep_pid1.peer_id_conflicts_with(ep_no_pid)
        False
        >>> ep_pid1.peer_id_conflicts_with(ep_pid2)
        True
        >>> ep_pid1.peer_id_conflicts_with(ep2_pid2)
        True
        >>> ep_pid2.peer_id_conflicts_with(ep2_pid2)
        False
        """
        return self.peer_id is not None and other.peer_id is not None and self.peer_id != other.peer_id
