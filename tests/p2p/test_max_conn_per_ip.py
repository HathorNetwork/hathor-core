from twisted.internet.address import IPv4Address

from hathor.simulator import FakeConnection
from tests.simulation.base import SimulatorTestCase


class PeerRelayTestCase(SimulatorTestCase):
    __test__ = True

    def test_max_conn_per_ip(self) -> None:
        m0 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)

        max_connections_per_ip = m0.connections.max_connections_per_ip
        for i in range(1, max_connections_per_ip + 8):
            m1 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)

            address = IPv4Address('TCP', '127.0.0.1', 1234 + i)
            conn = FakeConnection(m0, m1, latency=0.05, address2=address)
            self.simulator.add_connection(conn)

            self.simulator.run(10)

            if i <= max_connections_per_ip:
                self.assertFalse(conn.tr1.disconnected)
            else:
                self.assertTrue(conn.tr1.disconnected)
