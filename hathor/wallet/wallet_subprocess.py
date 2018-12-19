from hathor.mp_util import Process, Queue
from hathor.remote_clock import RemoteClockFactory, RemoteClockServicer
from hathor.wallet.remote_wallet import RemoteWalletFactory, RemoteWalletServicer
from hathor.wallet.wallet_resources import WalletResources


class WalletSubprocess(Process):
    def __init__(self, wallet_factory, remote_manager_factory, resource_listen_port=None, clock=None):
        # TODO: docstring
        Process.__init__(self)
        # this queue is used by the subprocess to inform which port was selected
        self._port_q = Queue(1)
        # this queue is used to inform the subprocess it can end
        self._exit_q = Queue(1)
        self._wallet_factory = wallet_factory
        self._remote_manager_factory = remote_manager_factory
        self._listen_port = resource_listen_port
        self.clock = clock

    def start(self):
        super().start()
        self._port = self._port_q.get()
        self.remote_wallet_factory = RemoteWalletFactory(self._port)
        if self.clock:
            self.remote_wallet_factory._remote_clock_factory = RemoteClockFactory(self._port)

    def stop(self):
        self._exit_q.put_nowait(None)
        # self.join()
        self.terminate()

    def run(self):
        """internal method for Process interface, DO NOT run directly!!"""
        from concurrent import futures

        import grpc
        from twister import web
        from twisted.internet import reactor

        from hathor import protos

        clock = self.clock or reactor

        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        port = grpc_server.add_insecure_port('127.0.0.1:0')
        grpc_server.start()
        self._port_q.put(port)

        manager = self._remote_manager_factory()
        tx_storage = manager.tx_storage
        wallet = self._wallet_factory(clock)
        wallet._manually_initialize()

        wallet_servicer = RemoteWalletServicer(wallet, tx_storage)
        protos.add_WalletServicer_to_server(wallet_servicer, grpc_server)

        if self.clock:
            clock_servicer = RemoteClockServicer(self.clock)
            protos.add_ClockServicer_to_server(clock_servicer, grpc_server)

        if self._listen_port is not None:
            wallet_resources = WalletResources(self.wallet)
            root = web.resource.Resource()
            root.putChild(b'wallet', wallet_resources)
            status_server = web.server.Site(root)
            reactor.listenTCP(self._listen_port, status_server)

        reactor.run()
        # XXX: this never actually advances past this point
        self._exit_q.get()
        grpc_server.stop(0)


class WalletSubprocessMock:
    def __init__(self, wallet_factory, remote_manager_factory, resource_listen_port=None, _with_remote_clock=False):
        self._wallet_factory = wallet_factory
        self._remote_manager_factory = remote_manager_factory
        self._listen_port = resource_listen_port
        self._with_remote_clock = _with_remote_clock

    def start(self):
        from concurrent import futures

        import grpc
        from twister import web
        from twisted.internet import reactor

        from hathor import protos

        clock = self.clock or reactor

        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        port = grpc_server.add_insecure_port('127.0.0.1:0')
        grpc_server.start()

        self.remote_wallet_factory = RemoteWalletFactory(port)
        if self.clock:
            self.remote_wallet_factory._remote_clock_factory = RemoteClockFactory(port)

        manager = self._remote_manager_factory()
        tx_storage = manager.tx_storage
        wallet = self._wallet_factory()
        wallet._manually_initialize()

        wallet_servicer = RemoteWalletServicer(wallet, tx_storage)
        protos.add_WalletServicer_to_server(wallet_servicer, grpc_server)

        if self._with_remote_clock:
            clock_servicer = RemoteClockServicer(clock)
            protos.add_ClockServicer_to_server(clock_servicer, grpc_server)

        if self._listen_port is not None:
            wallet_resources = WalletResources(self.wallet)
            root = web.resource.Resource()
            root.putChild(b'wallet', wallet_resources)
            status_server = web.server.Site(root)
            reactor.listenTCP(self._listen_port, status_server)

    def stop(self):
        self.grpc_server.stop(0)
