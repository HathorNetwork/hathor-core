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
from typing import Callable

from structlog import get_logger
from twisted.internet import defer
from twisted.names.client import lookupAddress, lookupText
from twisted.names.dns import Record_A, Record_TXT, RRHeader
from typing_extensions import override

from .peer_discovery import PeerDiscovery

logger = get_logger()


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

    @override
    async def discover_and_connect(self, connect_to: Callable[[str], None]) -> None:
        """ Run DNS lookup for host and connect to it
            This is executed when starting the DNS Peer Discovery and first connecting to the network
        """
        for host in self.hosts:
            url_list = await self.dns_seed_lookup(host)
            for url in url_list:
                connect_to(url)

    async def dns_seed_lookup(self, host: str) -> list[str]:
        """ Run a DNS lookup for TXT, A, and AAAA records and return a list of connection strings.
        """
        if self.test_mode:
            # Useful for testing purposes, so we don't need to execute a DNS query
            return ['tcp://127.0.0.1:40403']

        d1 = lookupText(host)
        d1.addCallback(self.dns_seed_lookup_text)
        d1.addErrback(self.errback),

        d2 = lookupAddress(host)
        d2.addCallback(self.dns_seed_lookup_address)
        d2.addErrback(self.errback),

        d = defer.gatherResults([d1, d2])
        results = await d
        unique_urls: set[str] = set()
        for urls in results:
            unique_urls.update(urls)
        return list(unique_urls)

    def errback(self, result):
        """ Return an empty list if any error occur.
        """
        self.log.error('errback', result=result)
        return []

    def dns_seed_lookup_text(
        self, results: tuple[list[RRHeader], list[RRHeader], list[RRHeader]]
    ) -> list[str]:
        """ Run a DNS lookup for TXT records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        ret: list[str] = []
        for record in answers:
            assert isinstance(record.payload, Record_TXT)
            for txt in record.payload.data:
                txt = txt.decode('utf-8')
                self.log.info('seed DNS TXT found', endpoint=txt)
                ret.append(txt)
        return ret

    def dns_seed_lookup_address(
        self, results: tuple[list[RRHeader], list[RRHeader], list[RRHeader]]
    ) -> list[str]:
        """ Run a DNS lookup for A records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        ret: list[str] = []
        for record in answers:
            assert isinstance(record.payload, Record_A)
            address = record.payload.address
            assert address is not None
            host = socket.inet_ntoa(address)
            txt = 'tcp://{}:{}'.format(host, self.default_port)
            self.log.info('seed DNS A found', endpoint=txt)
            ret.append(txt)
        return ret
