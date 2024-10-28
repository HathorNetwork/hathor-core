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
        manager.connections.connect_to_entrypoint(endpoint)

        self.assertIn(endpoint, manager.connections.iter_not_ready_endpoints())
        self.assertNotIn(endpoint, manager.connections.iter_ready_connections())
        self.assertNotIn(endpoint, manager.connections.iter_all_connections())
