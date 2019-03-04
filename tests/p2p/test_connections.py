import shutil
import tempfile

from hathor.manager import HathorManager
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import run_server


class ConnectionsTest(unittest.TestCase):
    def test_connections(self):
        process = run_server()
        process2 = run_server(listen=8006, status=8086, bootstrap='tcp:127.0.0.1:8005')
        process3 = run_server(listen=8007, status=8087, bootstrap='tcp:127.0.0.1:8005')

        process.terminate()
        process2.terminate()
        process3.terminate()

    def test_manager_connections(self):
        tx_storage = TransactionMemoryStorage()
        tmpdir = tempfile.mkdtemp(dir='/tmp/')
        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'teste')
        manager = HathorManager(self.clock, tx_storage=tx_storage, wallet=wallet)

        endpoint = 'tcp:127.0.0.1:8005'
        manager.connections.connect_to(endpoint, use_ssl=True)

        self.assertFalse(endpoint in manager.connections.connecting_peers)
        self.assertFalse(endpoint in manager.connections.handshaking_peers)
        self.assertFalse(endpoint in manager.connections.connected_peers)

        manager.stop()
        manager.stop()

        shutil.rmtree(tmpdir)
