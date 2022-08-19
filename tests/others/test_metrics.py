import tempfile
from unittest.mock import Mock

from hathor.manager import HathorManager
from hathor.metrics import Metrics
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.util import reactor
from hathor.wallet import Wallet
from tests import unittest


class MetricsTest(unittest.TestCase):
    def test_p2p_network_events(self):
        """Simulates publishing an event to pubsub the same way as done
           by the ConnectionsManager class.

           The expected result is that the Metrics class will use the info provided with
           the event to set its own fields related to the network peers
        """
        # Preparation
        tx_storage = TransactionMemoryStorage()
        pubsub = PubSubManager(reactor)

        metrics = Metrics(
            pubsub=pubsub,
            avg_time_between_blocks=30,
            tx_storage=tx_storage,
            reactor=reactor
        )

        metrics.start()

        # Execution
        pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTED,
            protocol=Mock(),
            peers_count={
                "connecting_peers_count": 3,
                "handshaking_peers_count": 4,
                "connected_peers_count": 5,
                "known_peers_count": 6
            }
        )

        # Assertion
        self.assertEquals(metrics.connecting_peers, 3)
        self.assertEquals(metrics.handshaking_peers, 4)
        self.assertEquals(metrics.connected_peers, 5)
        self.assertEquals(metrics.known_peers, 6)

    def test_connections_manager_integration(self):
        """Tests the integration with the ConnectionsManager class

           The expected result is that the both classes communicate through pubsub
           to update the Metrics class with info from ConnectionsManager class
        """
        # Preparation
        tx_storage = TransactionMemoryStorage()
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)
        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'teste')
        manager = HathorManager(self.clock, tx_storage=tx_storage, wallet=wallet)

        manager.metrics.start()

        manager.connections.peer_storage.update({"1": Mock(), "2": Mock(), "3": Mock()})
        manager.connections.connected_peers.update({"1": Mock(), "2": Mock()})
        manager.connections.handshaking_peers.update({Mock()})

        # Execution
        endpoint = 'tcp://127.0.0.1:8005'
        # This will trigger sending to the pubsub one of the network events
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.run_to_completion()

        # Assertion
        self.assertEquals(manager.metrics.known_peers, 3)
        self.assertEquals(manager.metrics.connected_peers, 2)
        self.assertEquals(manager.metrics.handshaking_peers, 1)
        self.assertEquals(manager.metrics.connecting_peers, 0)
