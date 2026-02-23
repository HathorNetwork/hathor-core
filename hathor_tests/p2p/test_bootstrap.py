from typing import Callable

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IProtocol
from twisted.names.dns import TXT, A, Record_A, Record_TXT, RRHeader
from typing_extensions import override

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_discovery import DNSPeerDiscovery, PeerDiscovery
from hathor.p2p.peer_discovery.dns import LookupResult
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint, Protocol
from hathor.p2p.peer_id import PeerId
from hathor.pubsub import PubSubManager
from hathor_tests import unittest
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock


class MockPeerDiscovery(PeerDiscovery):
    def __init__(self, mocked_addrs: list[tuple[str, int, str | None]]):
        self.mocked_addrs = mocked_addrs

    @override
    async def discover_and_connect(self, connect_to: Callable[[PeerEndpoint], Deferred[IProtocol] | None]) -> None:
        for host, port, peer_id_str in self.mocked_addrs:
            peer_id = PeerId(peer_id_str) if peer_id_str is not None else None
            connect_to(PeerAddress(Protocol.TCP, host, port).with_id(peer_id))


class MockDNSPeerDiscovery(DNSPeerDiscovery):
    def __init__(
        self,
        reactor: TestMemoryReactorClock,
        bootstrap_txt: list[tuple[str, int, str | None]],
        bootstrap_a: list[str],
    ):
        super().__init__(['test.example'])
        self.reactor = reactor
        self.mocked_lookup_a = [RRHeader(type=A, payload=Record_A(address)) for address in bootstrap_a]
        txt_entries = []
        for host, port, peer_id_str in bootstrap_txt:
            peer_id = PeerId(peer_id_str) if peer_id_str is not None else None
            addr_and_id = PeerAddress(Protocol.TCP, host, port).with_id(peer_id)
            txt_entries.append(str(addr_and_id).encode())
        self.mocked_lookup_txt = [RRHeader(type=TXT, payload=Record_TXT(*txt_entries))]

    def do_lookup_address(self, host: str) -> Deferred[LookupResult]:
        deferred: Deferred[LookupResult] = Deferred()
        lookup_result = [self.mocked_lookup_a, [], []]
        self.reactor.callLater(0, deferred.callback, lookup_result)
        return deferred

    def do_lookup_text(self, host: str) -> Deferred[LookupResult]:
        deferred: Deferred[LookupResult] = Deferred()
        lookup_result = [self.mocked_lookup_txt, [], []]
        self.reactor.callLater(0, deferred.callback, lookup_result)
        return deferred


class BootstrapTestCase(unittest.TestCase):
    def test_mock_discovery(self) -> None:
        pubsub = PubSubManager(self.clock)
        peer = PrivatePeer.auto_generated()
        connections = ConnectionsManager(
            self._settings,
            self.clock,
            peer,
            pubsub,
            True,
            self.rng,
            True,
            enable_ipv6=False,
            disable_ipv4=False
        )

        host_ports1 = [
            ('foobar', 1234, None),
            ('127.0.0.99', 9999, None),
            ('192.168.0.1', 1111, 'c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696')
        ]
        host_ports2 = [
            ('baz', 456, None),
            ('127.0.0.88', 8888, None),
            ('192.168.0.2', 2222, 'bc5119d47bb4ea7c19100bd97fb11f36970482108bd3d45ff101ee4f6bbec872')
        ]
        connections.add_peer_discovery(MockPeerDiscovery(host_ports1))
        connections.add_peer_discovery(MockPeerDiscovery(host_ports2))
        connections.do_discovery()
        self.clock.advance(1)
        connecting_addrs = {str(addr) for addr in connections._connections.connecting_outbound_peers()}
        self.assertEqual(connecting_addrs, {
            'tcp://foobar:1234',
            'tcp://127.0.0.99:9999',
            'tcp://baz:456',
            'tcp://127.0.0.88:8888',
            'tcp://192.168.0.1:1111',
            'tcp://192.168.0.2:2222',
        })

    def test_dns_discovery(self) -> None:
        pubsub = PubSubManager(self.clock)
        peer = PrivatePeer.auto_generated()
        connections = ConnectionsManager(
            self._settings,
            self.clock,
            peer,
            pubsub,
            True,
            self.rng,
            True,
            enable_ipv6=False,
            disable_ipv4=False
        )

        bootstrap_a = [
            '127.0.0.99',
            '127.0.0.88',
        ]
        bootstrap_txt = [
            ('foobar', 1234, None),
            ('baz', 456, None),
            ('192.168.0.1', 1111, 'c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696')
        ]
        connections.add_peer_discovery(MockDNSPeerDiscovery(self.clock, bootstrap_txt, bootstrap_a))
        connections.do_discovery()
        self.clock.advance(1)
        connecting_addrs = {str(addr) for addr in connections._connections.connecting_outbound_peers()}
        self.assertEqual(connecting_addrs, {
            'tcp://127.0.0.99:40403',
            'tcp://127.0.0.88:40403',
            'tcp://foobar:1234',
            'tcp://baz:456',
            'tcp://192.168.0.1:1111'
        })
