import grpc
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.task import Clock

from hathor.p2p.peer_id import PeerId
from hathor.manager import HathorManager
from hathor.wallet import Wallet, WalletSubprocessMock

from concurrent import futures
from unittest import main
from functools import partial
import tempfile
import shutil
import time


__all__ = [
    'TestCase',
    'main',
]


class StubWallet(Wallet):
    def __init__(self, *args, passwd, **kwargs):
        super().__init__(*args, **kwargs)
        self.unlock(passwd)
        self.generate_keys(count=20)
        self.lock()


class TestCase(unittest.TestCase):
    def setUp(self):
        from hathor.transaction.storage.remote_storage import TransactionRemoteStorageFactory
        from hathor.remote_manager import RemoteManagerFactory

        self.tmpdirs = []
        self.clock = Clock()
        self.clock.advance(time.time())
        self.grpc_server = grpc.server(futures.ThreadPoolExecutor())
        self.grpc_server_port = self.grpc_server.add_insecure_port('127.0.0.1:0')
        self.grpc_server.start()
        self.use_remote_wallet = False
        self.remote_tx_storage_factory = TransactionRemoteStorageFactory(self.grpc_server_port)
        self.remote_manager_factory = RemoteManagerFactory(self.grpc_server, self.remote_tx_storage_factory)
        self.managers = []

    def tearDown(self):
        for m in self.managers:
            m.stop()
        self.grpc_server.stop(0)
        self.clean_tmpdirs()

    def _create_test_wallet(self):
        """ Generate a Wallet with a number of keypairs for testing
            :rtype: Wallet
        """
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)

        if self.use_remote_wallet:
            wallet_factory = partial(StubWallet, directory=tmpdir, passwd=b'MYPASS')
            wallet_subprocess = WalletSubprocessMock(wallet_factory, self.remote_manager_factory)
            wallet_subprocess.start()
            wallet = wallet_subprocess.remote_wallet_factory()
        else:
            wallet = StubWallet(directory=tmpdir, passwd=b'MYPASS')
        return wallet

    def create_peer(self, network, peer_id=None, wallet=None, tx_storage=None, unlock_wallet=True):
        if peer_id is None:
            peer_id = PeerId()
        if not wallet:
            wallet = self._create_test_wallet()
            if unlock_wallet:
                wallet.unlock(b'MYPASS')
        manager = HathorManager(reactor, peer_id=peer_id, network=network, wallet=wallet,
                                tx_storage=tx_storage, test_mode=True, grpc_server_port=self.grpc_server_port,
                                clock=self.clock)
        manager.avg_time_between_blocks = 0.0001
        manager.add_grpc_servicers_to_server(self.grpc_server)
        manager.start()
        self.managers.append(manager)
        return manager

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
