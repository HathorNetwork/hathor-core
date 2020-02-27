import socket
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Generator, List, Set, Tuple

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
    def discover_and_connect(self, connect_to: Callable[[str], None]) -> Any:
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

    def discover_and_connect(self, connect_to: Callable[[str], None]) -> Any:
        for description in self.descriptions:
            connect_to(description)


class DNSPeerDiscovery(PeerDiscovery):
    """ It implements a DNS peer discovery, which looks for peers in A, AAA, and TXT records.
    """
    log = Logger()

    def __init__(self, hosts: List[str], default_port: int = 40403, test_mode: int = 0):
        """
        :param hosts: List of hosts to be queried
        :param default_port: Port number which will be used to connect when only IP address is available.
        """
        self.hosts = hosts
        self.default_port = default_port
        self.test_mode = test_mode

    @inlineCallbacks
    def discover_and_connect(self, connect_to: Callable[[str], None]) -> Generator[Any, Any, None]:
        """ Run DNS lookup for host and connect to it
            This is executed when starting the DNS Peer Discovery and first connecting to the network
        """
        for host in self.hosts:
            url_list = yield self.dns_seed_lookup(host)
            for url in url_list:
                connect_to(url)

    @inlineCallbacks
    def dns_seed_lookup(self, host: str) -> Generator[Any, Any, List[str]]:
        """ Run a DNS lookup for TXT, A, and AAAA records and return a list of connection strings.
        """
        if self.test_mode:
            # Useful for testing purposes, so we don't need to execute a DNS query
            return ['tcp://127.0.0.1:40403']

        d = defer.gatherResults([
            twisted.names.client.lookupText(host).addCallback(self.dns_seed_lookup_text),
            twisted.names.client.lookupAddress(host).addCallback(self.dns_seed_lookup_address),
        ])
        results = yield d
        unique_urls: Set[str] = set()
        for urls in results:
            unique_urls.update(urls)
        return list(unique_urls)

    def dns_seed_lookup_text(
        self, results: Tuple[List['RRHeader'], List['RRHeader'], List['RRHeader']]
    ) -> List[str]:
        """ Run a DNS lookup for TXT records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        ret: List[str] = []
        for record in answers:
            for txt in record.payload.data:
                txt = txt.decode('utf-8')
                self.log.info('Seed DNS TXT: {txt!r} found', txt=txt)
                ret.append(txt)
        return ret

    def dns_seed_lookup_address(
        self, results: Tuple[List['RRHeader'], List['RRHeader'], List['RRHeader']]
    ) -> List[str]:
        """ Run a DNS lookup for A records to discover new peers.

        The `results` has three lists that contain answer records, authority records, and additional records.
        """
        answers, _, _ = results
        ret: List[str] = []
        for record in answers:
            address = record.payload.address
            host = socket.inet_ntoa(address)
            txt = 'tcp://{}:{}'.format(host, self.default_port)
            self.log.info('Seed DNS A: {host!r} found, connecting to {txt!r}', host=host, txt=txt)
            ret.append(txt)
        return ret
