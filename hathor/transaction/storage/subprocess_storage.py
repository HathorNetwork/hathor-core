from concurrent import futures
from multiprocessing import Process, Queue

import grpc

from hathor.exception import HathorError
from hathor.transaction.storage.remote_storage import TransactionRemoteStorage, create_transaction_storage_server


class SubprocessNotAliveError(HathorError):
    pass


class TransactionSubprocessStorage(TransactionRemoteStorage, Process):
    """Subprocess storage to be used 'on top' of other storages.

    Wraps a given store constructor and spawns it on a subprocess.
    """

    def __init__(self, store_constructor, with_index=None):
        """
        :param store_constructor: a callable that returns an instance of TransactionStorage
        :type store_constructor: :py:class:`typing.Callable[..., hathor.transaction.storage.TransactionStorage]`
        """
        Process.__init__(self)
        TransactionRemoteStorage.__init__(self, with_index=with_index)
        self._store_constructor = store_constructor
        # this queue is used by the subprocess to inform which port was selected
        self._port_q = Queue(1)
        # this queue is used to inform the subprocess it can end
        self._exit_q = Queue(1)

    def _check_connection(self):
        """raise error if subprocess is not alive"""
        super()._check_connection()
        if not self.is_alive():
            raise SubprocessNotAliveError('subprocess is dead')

    def stop(self):
        self._exit_q.put(None)
        if self._channel:
            self._channel.close()

    def start(self):
        super().start()
        port = self._port_q.get()
        self.connect_to(port)

    def terminate(self):
        self.close()
        super().terminate()

    def run(self):
        """internal method for Process interface, do not run directly"""
        # TODO: some tuning with benchmarks
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        tx_storage = self._store_constructor()
        tx_storage._manually_initialize()
        _servicer, port = create_transaction_storage_server(server, tx_storage)
        self._port_q.put(port)
        server.start()
        self._exit_q.get()
        # the above all blocks until _exit_q.put(None) or _exit_q closes
        server.stop(0)
