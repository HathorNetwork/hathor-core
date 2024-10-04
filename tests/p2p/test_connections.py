import sys

import pytest

from hathor.p2p.entrypoint import Entrypoint
from tests import unittest
from tests.utils import run_server


class ConnectionsTest(unittest.TestCase):
    @pytest.mark.skipif(sys.platform == 'win32', reason='run_server is very finicky on Windows')
    def test_connections(self) -> None:
        process = run_server()
        process2 = run_server(listen=8006, status=8086, bootstrap='tcp://127.0.0.1:8005')
        process3 = run_server(listen=8007, status=8087, bootstrap='tcp://127.0.0.1:8005')

        process.terminate()
        process2.terminate()
        process3.terminate()

    def test_manager_connections(self) -> None:
        manager = self.create_peer('testnet', enable_sync_v1=True, enable_sync_v2=False)

        endpoint = Entrypoint.parse('tcp://127.0.0.1:8005')
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.assertIn(endpoint, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint, manager.connections.iter_ready_connections())
        self.assertNotIn(endpoint, manager.connections.iter_all_connections())

    def test_manager_disabled_ipv6(self) -> None:
        """Should not try to connect to ipv6 peers if ipv6 is disabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=False,
            disable_ipv4=False
        )

        endpoint = Entrypoint.parse('tcp://[::1]:8005')
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.assertNotIn(endpoint, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint, manager.connections.iter_ready_connections())
        self.assertNotIn(endpoint, manager.connections.iter_all_connections())

    def test_manager_enabled_ipv6_and_ipv4(self) -> None:
        """Should connect to both ipv4 and ipv6 peers if both are enabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=True,
            disable_ipv4=False
        )

        endpoint_ipv6 = Entrypoint.parse('tcp://[::1]:8005')
        manager.connections.connect_to(endpoint_ipv6, use_ssl=True)

        endpoint_ipv4 = Entrypoint.parse('tcp://127.0.0.1:8005')
        manager.connections.connect_to(endpoint_ipv4, use_ssl=True)

        self.assertIn(endpoint_ipv4, manager.connections.iter_not_ready_endpoints())
        self.assertIn(endpoint_ipv6, manager.connections.iter_not_ready_endpoints())

        self.assertNotIn(endpoint_ipv4, manager.connections.iter_ready_connections())
        self.assertNotIn(endpoint_ipv6, manager.connections.iter_ready_connections())

        self.assertNotIn(endpoint_ipv4, manager.connections.iter_all_connections())
        self.assertNotIn(endpoint_ipv6, manager.connections.iter_all_connections())

    def test_manager_disabled_ipv4(self) -> None:
        """Should not try to connect to ipv4 peers if ipv4 is disabled"""

        manager = self.create_peer(
            'testnet',
            enable_sync_v1=False,
            enable_sync_v2=True,
            enable_ipv6=True,
            disable_ipv4=True,
        )

        endpoint = Entrypoint.parse('tcp://127.0.0.1:8005')
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.assertNotIn(endpoint, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint, manager.connections.iter_ready_connections())
        self.assertNotIn(endpoint, manager.connections.iter_all_connections())
