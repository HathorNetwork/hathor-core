import socket
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Generator, List, Optional, Tuple

import twisted.names.client
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger

if TYPE_CHECKING:
    from twisted.names.dns import RRHeader  # noqa: F401


class PeerDiscovery(ABC):
    """ Base class to implement peer discovery strategies.
    """

    @abstractmethod
    def discover_and_connect(self, connect_to: Callable[[str], None]):
        """ This method must discover the peers and call `connect_to` for each of them.

        :param connect_to: Function which will be called for each discovered peer.
        :type connect_to: function
        """
        raise NotImplementedError


class BootstrapPeerDiscovery(PeerDiscovery):
    """ It implements a bootstrap peer discovery, which receives a static list of peers.
    """
    log = Logger()

    def __init__(self, descriptions: List[str]):
        """
        :param descriptions: Descriptions of peers to connect to.
        """
        super().__init__()
        self.descriptions = descriptions

    def discover_and_connect(self, connect_to: Callable[[str], None]):
        for description in self.descriptions:
            connect_to(description)


class DNSPeerDiscovery(PeerDiscovery):
    """ It implements a DNS peer discovery, which looks for peers in A, AAA, and TXT records.
    """
    log = Logger()

    connect_to: Optional[Callable[[str], None]]

    def __init__(self, hosts: List[str], default_port: int = 40403, test_mode: int = 0):
        """
        :param hosts: List of hosts to be queried
        :param default_port: Port number which will be used to connect when only IP address is available.
        """
        self.hosts = hosts
        self.default_port = default_port
        self.test_mode = test_mode
        self.connect_to = None

    @inlineCallbacks
    def discover_and_connect(self, connect_to: Callable[[str], None]) -> Generator[Any, Any, None]:
        """ Run DNS lookup for host and connect to it
            This is executed when starting the DNS Peer Discovery and first connecting to the network
        """
        self.connect_to = connect_to
        for host in self.hosts:
            url = yield self.dns_seed_lookup(host)
            if url:
                self.connect_to(url)

    @inlineCallbacks
    def dns_seed_lookup(self, host: str) -> Generator[Any, Any, Optional[str]]:
        """ Run a DNS lookup for TXT, A, and AAAA records and return the first result found.
        """
        if self.test_mode:
            # Useful for testing purposes, so we don't need to execute a DNS query
            return 'tcp://127.0.0.1:40403'

        d = defer.gatherResults([
            twisted.names.client.lookupText(host).addCallback(self.dns_seed_lookup_text),
            twisted.names.client.lookupAddress(host).addCallback(self.dns_seed_lookup_address),
        ])
        results = yield d
        for result in results:
            if result is not None:
                return result

        return None

    def dns_seed_lookup_text(
        self, text_results: Tuple[List['RRHeader'], List['RRHeader'], List['RRHeader']]
    ) -> Optional[str]:
        """ Run a DNS lookup for TXT records to discover new peers.
        """
        if text_results:
            answers, _, _ = text_results
            if answers:
                url = self.on_dns_seed_found(answers)
                return url
        return None

    def dns_seed_lookup_address(
        self, address_results: Tuple[List['RRHeader'], List['RRHeader'], List['RRHeader']]
    ) -> Optional[str]:
        """ Run a DNS lookup for A records to discover new peers.
        """
        if address_results:
            answers, _, _ = address_results
            if answers:
                url = self.on_dns_seed_found_ipv4(answers)
                return url
        return None

    def dns_seed_lookup_ipv6_address(self, host: str) -> None:
        """ Run a DNS lookup for AAAA records to discover new peers.
        """
        x = twisted.names.client.lookupIPV6Address(host)
        x.addCallback(self.on_dns_seed_found_ipv6)

    def on_dns_seed_found(self, answers: List['RRHeader']) -> Optional[str]:
        """ Executed only when a new peer is discovered by `dns_seed_lookup_text`.
        """
        for x in answers:
            data = x.payload.data
            for txt in data:
                txt = txt.decode('utf-8')
                self.log.info('Seed DNS TXT: {txt!r} found', txt=txt)
                return txt
        return None

    def on_dns_seed_found_ipv4(self, answers: List['RRHeader']) -> Optional[str]:
        """ Executed only when a new peer is discovered by `dns_seed_lookup_address`.
        """
        for x in answers:
            address = x.payload.address
            host = socket.inet_ntoa(address)
            self.log.info('Seed DNS A: {host!r} found', host=host)
            return 'tcp://{}:{}'.format(host, self.default_port)
        return None

    def on_dns_seed_found_ipv6(self, results):
        """ Executed only when a new peer is discovered by `dns_seed_lookup_ipv6_address`.
        """
        # answers, _, _ = results
        # for x in answers:
        #     address = x.payload.address
        #     host = socket.inet_ntop(socket.AF_INET6, address)
        raise NotImplementedError
