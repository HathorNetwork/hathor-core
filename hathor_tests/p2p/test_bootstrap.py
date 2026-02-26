from typing import Callable

from twisted.internet.defer import Deferred
from twisted.names.dns import TXT, A, Record_A, Record_TXT, RRHeader
from typing_extensions import override

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_discovery import DNSPeerDiscovery, PeerDiscovery
from hathor.p2p.peer_discovery.dns import LookupResult
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint, Protocol
from hathor.pubsub import PubSubManager
from hathor_tests import unittest
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock


class MockPeerDiscovery(PeerDiscovery):
    def __init__(self, mocked_host_ports: list[tuple[str, int]]):
        self.mocked_host_ports = mocked_host_ports

    @override
    async def discover_and_connect(self, connect_to_endpoint: Callable[[PeerEndpoint], None]) -> None:
        for host, port in self.mocked_host_ports:
            addr = PeerAddress(Protocol.TCP, host, port)
            connect_to_endpoint(addr.with_id())


class MockDNSPeerDiscovery(DNSPeerDiscovery):
    def __init__(self, reactor: TestMemoryReactorClock, bootstrap_txt: list[tuple[str, int]], bootstrap_a: list[str]):
        super().__init__(['test.example'])
        self.reactor = reactor
        self.mocked_lookup_a = [RRHeader(type=A, payload=Record_A(address)) for address in bootstrap_a]
        txt_entries = [f'tcp://{h}:{p}'.encode() for h, p in bootstrap_txt]
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
            None,
            enable_ipv6=False,
            disable_ipv4=False
        )

        host_ports1 = [
            ('foobar', 1234),
            ('127.0.0.99', 9999),
        ]
        host_ports2 = [
            ('baz', 456),
            ('127.0.0.88', 8888),
        ]
        connections.add_peer_discovery(MockPeerDiscovery(host_ports1))
        connections.add_peer_discovery(MockPeerDiscovery(host_ports2))
        connections.do_discovery()
        self.clock.advance(1)
        connecting_entrypoints = {str(entrypoint) for entrypoint, _ in connections.connecting_peers.values()}
        self.assertEqual(connecting_entrypoints, {
            'tcp://foobar:1234',
            'tcp://127.0.0.99:9999',
            'tcp://baz:456',
            'tcp://127.0.0.88:8888',
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
            None,
            enable_ipv6=False,
            disable_ipv4=False
        )

        bootstrap_a = [
            '127.0.0.99',
            '127.0.0.88',
        ]
        bootstrap_txt = [
            ('foobar', 1234),
            ('baz', 456),
        ]
        connections.add_peer_discovery(MockDNSPeerDiscovery(self.clock, bootstrap_txt, bootstrap_a))
        connections.do_discovery()
        self.clock.advance(1)
        connecting_entrypoints = {str(entrypoint) for entrypoint, _ in connections.connecting_peers.values()}
        self.assertEqual(connecting_entrypoints, {
            'tcp://127.0.0.99:40403',
            'tcp://127.0.0.88:40403',
            'tcp://foobar:1234',
            'tcp://baz:456',
        })
