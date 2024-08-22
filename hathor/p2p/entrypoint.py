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

from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from typing_extensions import Self

from hathor.p2p.peer_id import PeerId
from hathor.reactor import ReactorProtocol as Reactor


class Protocol(Enum):
    TCP = 'tcp'


@dataclass(frozen=True, slots=True)
class Entrypoint:
    """Endpoint description (returned from DNS query, or received from the p2p network) may contain a peer-id."""

    protocol: Protocol
    host: str
    port: int
    peer_id: PeerId | None = None

    def __str__(self):
        if self.peer_id is None:
            return f'{self.protocol.value}://{self.host}:{self.port}'
        else:
            return f'{self.protocol.value}://{self.host}:{self.port}/?id={self.peer_id}'

    @classmethod
    def parse(cls, description: str) -> Self:
        """Parse endpoint description into an Entrypoint object.

        Examples:

        >>> str(Entrypoint.parse('tcp://127.0.0.1:40403/'))
        'tcp://127.0.0.1:40403'

        >>> id1 = 'c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}')
        Entrypoint(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403, \
peer_id=PeerId('c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'))

        >>> str(Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}'))
        'tcp://127.0.0.1:40403/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'

        >>> Entrypoint.parse('tcp://127.0.0.1:40403')
        Entrypoint(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403, peer_id=None)

        >>> Entrypoint.parse('tcp://127.0.0.1:40403/')
        Entrypoint(protocol=<Protocol.TCP: 'tcp'>, host='127.0.0.1', port=40403, peer_id=None)

        >>> Entrypoint.parse('tcp://foo.bar.baz:40403/')
        Entrypoint(protocol=<Protocol.TCP: 'tcp'>, host='foo.bar.baz', port=40403, peer_id=None)

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
        ValueError: expected a port

        >>> Entrypoint.parse('tcp://:40403/')
        Traceback (most recent call last):
        ...
        ValueError: expected a host

        >>> Entrypoint.parse('tcp://127.0.0.1:40403/foo')
        Traceback (most recent call last):
        ...
        ValueError: unexpected path: /foo

        >>> id2 = 'bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> Entrypoint.parse(f'tcp://127.0.0.1:40403/?id={id1}&id={id2}')
        Traceback (most recent call last):
        ...
        ValueError: unexpected id count: 2
        """
        url = urlparse(description)
        protocol = Protocol(url.scheme)
        host = url.hostname
        if host is None:
            raise ValueError('expected a host')
        port = url.port
        if port is None:
            raise ValueError('expected a port')
        if url.path not in {'', '/'}:
            raise ValueError(f'unexpected path: {url.path}')
        peer_id: PeerId | None = None

        if url.query:
            query = parse_qs(url.query)
            if 'id' in query:
                ids = query['id']
                if len(ids) != 1:
                    raise ValueError(f'unexpected id count: {len(ids)}')
                peer_id = PeerId(ids[0])

        return cls(protocol, host, port, peer_id)

    @classmethod
    def from_hostname_address(cls, hostname: str, address: IPv4Address | IPv6Address) -> Self:
        return cls.parse(f'{address.type}://{hostname}:{address.port}')

    def to_client_endpoint(self, reactor: Reactor) -> IStreamClientEndpoint:
        """This method generates a twisted client endpoint that has a .connect() method."""
        # XXX: currently we don't support IPv6, but when we do we have to decide between TCP4ClientEndpoint and
        # TCP6ClientEndpoint, when the host is an IP address that is easy, but when it is a DNS hostname, we will not
        # know which to use until we know which resource records it holds (A or AAAA)
        return TCP4ClientEndpoint(reactor, self.host, self.port)

    def equals_ignore_peer_id(self, other: Self) -> bool:
        """Compares `self` and `other` ignoring the `peer_id` fields of either.

        Examples:

        >>> ep1 = 'tcp://foo:111'
        >>> ep2 = 'tcp://foo:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep3 = 'tcp://foo:111/?id=bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872'
        >>> ep4 = 'tcp://bar:111/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
        >>> ep5 = 'tcp://foo:112/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696'
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
        """
        return (self.protocol, self.host, self.port) == (other.protocol, other.host, other.port)

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

    def is_localhost(self) -> bool:
        """Used to determine if the entrypoint host is a localhost address.

        Examples:

        >>> Entrypoint.parse('tcp://127.0.0.1:444').is_localhost()
        True
        >>> Entrypoint.parse('tcp://localhost:444').is_localhost()
        True
        >>> Entrypoint.parse('tcp://8.8.8.8:444').is_localhost()
        False
        >>> Entrypoint.parse('tcp://foo.bar:444').is_localhost()
        False
        """
        if self.host == '127.0.0.1':
            return True
        if self.host == 'localhost':
            return True
        return False
