from tests import unittest
from tests.utils import run_server


class ConnectionsTest(unittest.TestCase):
    def test_connections(self):
        process = run_server()
        process2 = run_server(listen=8006, status=8086, bootstrap='tcp:127.0.0.1:8005')

        process.terminate()
        process2.terminate()
