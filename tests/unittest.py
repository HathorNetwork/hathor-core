import grpc
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.task import Clock

from hathor.p2p.peer_id import PeerId
from hathor.manager import HathorManager
from hathor.wallet import Wallet, WalletManager

from concurrent import futures
import tempfile
import shutil
import time


class TestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdirs = []
        self.clock = Clock()
        self.clock.advance(time.time())
        self.grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        # self.grpc_server.start()

    def tearDown(self):
        self.grpc_server.stop(0)
        self.clean_tmpdirs()

    def _create_test_wallet(self):
        """ Generate a Wallet with a number of keypairs for testing
            :rtype: Wallet
        """
        tmpdir = tempfile.mkdtemp(dir='/tmp/')
        self.tmpdirs.append(tmpdir)

        wallet = Wallet(directory=tmpdir)
        wallet.unlock(b'MYPASS')
        wallet.generate_keys(count=20)
        wallet.lock()
        return wallet

    def create_peer(self, network, peer_id=None, wallet=None, tx_storage=None, unlock_wallet=True):
        if peer_id is None:
            peer_id = PeerId()
        if not wallet:
            wallet = self._create_test_wallet()
            if unlock_wallet:
                wallet.unlock(b'MYPASS')
        manager = HathorManager(self.clock, peer_id=peer_id, network=network, wallet=wallet, tx_storage=tx_storage)
        manager.avg_time_between_blocks = 0.0001
        manager.test_mode = True
        manager.start()
        return manager

    def create_peer_for_wallet(self, network, peer_id=None, wallet=None, unlock_wallet=True):
        from hathor.remote_manager import create_manager_server, RemoteManager
        from hathor.transaction.storage import create_transaction_storage_server, TransactionRemoteStorage

        manager = self.create_peer(network, peer_id=peer_id, wallet=wallet, unlock_wallet=unlock_wallet)
        manager_servicer, manager_port = create_manager_server(self.grpc_server, manager)
        tx_storage_servicer, tx_storage_port = create_transaction_storage_server(self.grpc_server, manager.tx_storage)
        self.grpc_server.start()

        remote_manager = RemoteManager()
        remote_manager.connect_to(manager_port)

        remote_tx_storage = TransactionRemoteStorage()
        remote_tx_storage.connect_to(tx_storage_port)

        wallet_manager = WalletManager(manager.wallet, remote_tx_storage, remote_manager, reactor=manager.reactor)
        return manager, wallet_manager

    def clean_tmpdirs(self):
        for tmpdir in self.tmpdirs:
            shutil.rmtree(tmpdir)

    def clean_pending(self, required_to_quiesce=True):
        """
        This handy method cleans all pending tasks from the reactor.

        When writing a unit test, consider the following question:

            Is the code that you are testing required to release control once it
            has done its job, so that it is impossible for it to later come around
            (with a delayed reactor task) and do anything further?

        If so, then trial will usefully test that for you -- if the code under
        test leaves any pending tasks on the reactor then trial will fail it.

        On the other hand, some code is *not* required to release control -- some
        code is allowed to continuously maintain control by rescheduling reactor
        tasks in order to do ongoing work.  Trial will incorrectly require that
        code to clean up all its tasks from the reactor.

        Most people think that such code should be amended to have an optional
        "shutdown" operation that releases all control, but on the contrary it is
        good design for some code to *not* have a shutdown operation, but instead
        to have a "crash-only" design in which it recovers from crash on startup.

        If the code under test is of the "long-running" kind, which is *not*
        required to shutdown cleanly in order to pass tests, then you can simply
        call testutil.clean_pending() at the end of the unit test, and trial will
        be satisfied.

        Copy from: https://github.com/zooko/pyutil/blob/master/pyutil/testutil.py#L68
        """
        pending = reactor.getDelayedCalls()
        active = bool(pending)
        for p in pending:
            if p.active():
                p.cancel()
            else:
                print('WEIRDNESS! pending timed call not active!')
        if required_to_quiesce and active:
            self.fail('Reactor was still active when it was required to be quiescent.')
