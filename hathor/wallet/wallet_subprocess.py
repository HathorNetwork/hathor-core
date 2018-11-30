from concurrent import futures
from multiprocessing import Process, Queue

import grpc
from twisted.web import server, resource

from hathor.exception import HathorError
from hathor.transaction.storage.remote_storage import create_transaction_storage_server
from hathor.remote_manager import RemoteManager
from hathor.transaction.storage import TransactionRemoteStorage
from hathor.wallet.wallet_manager import WalletManager
from hathor.wallet.wallet_resources import WalletResources


class WalletSubprocess(Process):
    def __init__(self, wallet_constructor, tx_storage_port, manager_port, listen_port):
        # TODO: docstring
        Process.__init__(self)
        self._wallet_constructor = wallet_constructor

        self._tx_storage_port = tx_storage_port
        self._manager_port = manager_port
        self._listen_port = listen_port

    def run(self):
        """internal method for Process interface, DO NOT run directly!!"""
        from twisted.internet import reactor

        # TODO: some tuning with benchmarks
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        self._reactor = reactor

        self.wallet = self._wallet_constructor()
        self.wallet._manually_initialize()
        self._remote_manager = RemoteManager()
        self._remote_manager.connect_to(self._manager_port)
        self._tx_storage = TransactionRemoteStorage()
        self._tx_storage.connect_to(self._tx_storage_port)
        self.wallet_manager = WalletManager(self.wallet, self._tx_storage, self._remote_manager, reactor=self._reactor)
        self.wallet_resources = WalletResources(self.wallet_manager)

        self._root = resource.Resource()
        self._root.putChild(b'wallet', self.wallet_resources)
        self._status_server = server.Site(self._root)
        self._reactor.listenTCP(self._listen_port, self._status_server)
        self._reactor.run()
