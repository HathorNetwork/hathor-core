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

import socket
from collections.abc import Iterator
from itertools import chain
from typing import Callable, TypeAlias

from structlog import get_logger
from twisted.internet.defer import Deferred, gatherResults
from twisted.names.client import lookupAddress, lookupText
from twisted.names.dns import Record_A, Record_TXT, RRHeader
from typing_extensions import override

from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint, Protocol

from .peer_discovery import PeerDiscovery

logger = get_logger()

LookupResult: TypeAlias = tuple[list[RRHeader], list[RRHeader], list[RRHeader]]


class DNSPeerDiscovery(PeerDiscovery):
    """ It implements a DNS peer discovery, which looks for peers in A, AAA, and TXT records.
    """

    def __init__(self, hosts: list[str], default_port: int = 40403, test_mode: int = 0):
        """
        :param hosts: List of hosts to be queried
        :param default_port: Port number which will be used to connect when only IP address is available.
        """
        self.log = logger.new()
        self.hosts = hosts
        self.default_port = default_port
        self.test_mode = test_mode

    def do_lookup_address(self, host: str) -> Deferred[LookupResult]:
        return lookupAddress(host)

    def do_lookup_text(self, host: str) -> Deferred[LookupResult]:
        return lookupText(host)

    @override
    async def discover_and_connect(self, connect_to_endpoint: Callable[[PeerEndpoint], None]) -> None:
        """ Run DNS lookup for host and connect to it
            This is executed when starting the DNS Peer Discovery and first connecting to the network
        """
        for host in self.hosts:
            for entrypoint in (await self.dns_seed_lookup(host)):
                connect_to_endpoint(entrypoint, discovery_call=True)  # type: ignore[call-arg]

    async def dns_seed_lookup(self, host: str) -> set[PeerEndpoint]:
        """ Run a DNS lookup for TXT, A, and AAAA records and return a list of connection strings.
        """
        if self.test_mode:
            # Useful for testing purposes, so we don't need to execute a DNS query
            return {PeerEndpoint.parse('tcp://127.0.0.1:40403')}

        deferreds: list[Deferred[Iterator[PeerEndpoint]]] = []

        d1 = self.do_lookup_text(host) \
            .addCallback(self.dns_seed_lookup_text) \
            .addErrback(self.errback)
        deferreds.append(d1)

        d2 = self.do_lookup_address(host) \
            .addCallback(self.dns_seed_lookup_address) \
            .addErrback(self.errback)
        deferreds.append(d2)

        results: list[Iterator[PeerEndpoint]] = await gatherResults(deferreds)
        return set(chain(*results))

    def errback(self, result):
        """ Return an empty list if any error occur.
        """
        self.log.error('errback', result=result)
        return []

    def dns_seed_lookup_text(self, results: LookupResult) -> Iterator[PeerEndpoint]:
        """ Run a DNS lookup for TXT records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        for record in answers:
            assert isinstance(record.payload, Record_TXT)
            for txt in record.payload.data:
                raw_entrypoint = txt.decode('utf-8')
                try:
                    entrypoint = PeerEndpoint.parse(raw_entrypoint)
                except ValueError:
                    self.log.warning('could not parse entrypoint, skipping it', raw_entrypoint=raw_entrypoint)
                    continue
                self.log.info('seed DNS TXT found', entrypoint=str(entrypoint))
                yield entrypoint

    def dns_seed_lookup_address(self, results: LookupResult) -> Iterator[PeerEndpoint]:
        """ Run a DNS lookup for A records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        for record in answers:
            assert isinstance(record.payload, Record_A)
            address = record.payload.address
            assert address is not None
            host = socket.inet_ntoa(address)
            entrypoint = PeerAddress(Protocol.TCP, host, self.default_port).with_id()
            self.log.info('seed DNS A found', entrypoint=str(entrypoint))
            yield entrypoint
