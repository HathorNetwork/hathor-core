from hathor.exception import HathorError
from hathor.mp_util import Process, Queue
from hathor.remote_clock import RemoteClockFactory, RemoteClockServicer
from hathor.transaction.storage.remote_storage import (TransactionRemoteStorage, TransactionRemoteStorageFactory,
                                                       TransactionStorageServicer)


class SubprocessNotAliveError(HathorError):
    pass


class TransactionSubprocessStorage(TransactionRemoteStorage, Process):
    """Subprocess storage to be used 'on top' of other storages.

    Wraps a given store constructor and spawns it on a subprocess.
    """

    def __init__(self, tx_storage_factory, with_index=None, _with_remote_clock=False):
        """
        :param tx_storage_factory: a callable that returns an instance of ITransactionStorage
        :type tx_storage_factory: :py:class:`typing.Callable[..., hathor.transaction.storage.ITransactionStorage]`
        """
        Process.__init__(self)
        TransactionRemoteStorage.__init__(self, with_index=with_index)
        self._tx_storage_factory = tx_storage_factory
        # this queue is used by the subprocess to inform which port was selected
        self._port_q = Queue(1)
        # this queue is used to inform the subprocess it can end
        self._exit_q = Queue(1)
        self._with_remote_clock = _with_remote_clock

    def _check_connection(self):
        """raise error if subprocess is not alive"""
        super()._check_connection()
        if not self.is_alive():
            raise SubprocessNotAliveError('subprocess is dead')

    def start(self):
        super().start()
        port = self._port_q.get()
        self.connect_to(port)
        self.factory = TransactionRemoteStorageFactory(port)
        if self._with_remote_clock:
            self.remote_clock_factory = RemoteClockFactory(self._port)

    def stop(self):
        self._exit_q.put(None)
        self.disconnect()
        self.join()
        # self.terminate()

    def run(self):
        """internal method for Process interface, do not run directly"""
        from concurrent import futures

        import grpc
        from twisted.internet import reactor

        from hathor import protos

        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        port = grpc_server.add_insecure_port('127.0.0.1:0')
        grpc_server.start()
        self._port_q.put(port)

        tx_storage = self._tx_storage_factory()
        tx_storage._manually_initialize()
        tx_storage_servier = TransactionStorageServicer(tx_storage)
        protos.add_TransactionStorageServicer_to_server(tx_storage_servier, grpc_server)

        if self._with_remote_clock:
            clock_servicer = RemoteClockServicer(reactor)
            protos.add_ClockServicer_to_server(clock_servicer, grpc_server)

        self._exit_q.get()
        grpc_server.stop(0)
