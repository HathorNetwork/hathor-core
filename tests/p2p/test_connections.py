from hathor.manager import HathorManager
from hathor.p2p.peer_endpoint import PeerEndpoint
from tests import unittest
from tests.utils import run_server


class ConnectionsTest(unittest.TestCase):
    def test_connections(self) -> None:
        process = run_server()
        process2 = run_server(listen=8006, status=8086, bootstrap='tcp://127.0.0.1:8005')
        process3 = run_server(listen=8007, status=8087, bootstrap='tcp://127.0.0.1:8005')

        process.terminate()
        process2.terminate()
        process3.terminate()

    def test_manager_connections(self) -> None:
        manager: HathorManager = self.create_peer('testnet', enable_sync_v1=True, enable_sync_v2=False)

        endpoint = PeerEndpoint.parse('tcp://127.0.0.1:8005')
        manager.connections.connect_to(endpoint)

        self.assertIn(endpoint.addr, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint.addr, [conn.addr for conn in manager.connections.iter_ready_connections()])
        self.assertNotIn(endpoint.addr, [conn.addr for conn in manager.connections.get_connected_peers()])

    def test_manager_disabled_ipv6(self) -> None:
        """Should not try to connect to ipv6 peers if ipv6 is disabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=False,
            disable_ipv4=False
        )

        endpoint = PeerEndpoint.parse('tcp://[::1]:8005')
        manager.connections.connect_to(endpoint)

        self.assertNotIn(endpoint.addr, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint.addr, [conn.addr for conn in manager.connections.iter_ready_connections()])
        self.assertNotIn(endpoint.addr, [conn.addr for conn in manager.connections.get_connected_peers()])

    def test_manager_enabled_ipv6_and_ipv4(self) -> None:
        """Should connect to both ipv4 and ipv6 peers if both are enabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=True,
            disable_ipv4=False
        )

        endpoint_ipv6 = PeerEndpoint.parse('tcp://[::3:2:1]:8005')
        manager.connections.connect_to(endpoint_ipv6)

        endpoint_ipv4 = PeerEndpoint.parse('tcp://1.2.3.4:8005')
        manager.connections.connect_to(endpoint_ipv4)

        self.assertIn(endpoint_ipv4.addr, manager.connections.iter_not_ready_endpoints())
        self.assertIn(endpoint_ipv6.addr, manager.connections.iter_not_ready_endpoints())

        self.assertEqual(2, len(list(manager.connections.iter_not_ready_endpoints())))
        self.assertEqual(0, len(list(manager.connections.iter_ready_connections())))
        self.assertEqual(0, len(list(manager.connections.get_connected_peers())))

    def test_manager_disabled_ipv4(self) -> None:
        """Should not try to connect to ipv4 peers if ipv4 is disabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=True,
            disable_ipv4=True,
        )

        endpoint = PeerEndpoint.parse('tcp://127.0.0.1:8005')
        manager.connections.connect_to(endpoint)

        self.assertEqual(0, len(list(manager.connections.iter_not_ready_endpoints())))
        self.assertEqual(0, len(list(manager.connections.iter_ready_connections())))
        self.assertEqual(0, len(list(manager.connections.get_connected_peers())))
