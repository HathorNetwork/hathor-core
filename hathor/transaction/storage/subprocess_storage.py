# encoding: utf-8
import collections
from concurrent import futures
from multiprocessing import Process, Queue
import time

import grpc
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.logger import Logger

from hathor import protos
from hathor.exception import HathorError
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.util import deprecated, skip_warning


class SubprocessNotAliveError(HathorError):
    pass


class TransactionSubprocessStorage(TransactionStorage, Process):
    """Subprocess storage to be used 'on top' of other storages.

    Wraps a given store constructor and spawns it on a subprocess.
    """
    log = Logger()


    def __init__(self, store_constructor, with_index=True):
        """
        :param store_constructor: a callable that returns an instance of TransactionStorage
        :type store_constructor: :py:class:`typing.Callable[..., hathor.transaction.storage.transaction_storage.TransactionStorage]`
        """
        Process.__init__(self)
        TransactionStorage.__init__(self, with_index=with_index)
        self._store_constructor = store_constructor
        self._client = None
        self._channel = None
        # this queue is used by the subprocess to inform which port was selected
        self._port_q = Queue(1)
        # this queue is used to inform the subprocess it can end
        self._exit_q = Queue(1)

    def _ensure_alive(self):
        """raise error if subprocess is not alive"""
        if not self._channel:
            raise SubprocessNotAliveError('subprocess not started')
        if not self.is_alive():
            raise SubprocessNotAliveError('subprocess is dead')

    def stop(self):
        self._exit_q.put(None)
        if self._channel:
            self._channel.close()

    # multiporcessing.Process interface implementation

    def start(self):
        super().start()
        port = self._port_q.get()
        self._channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self._stub = protos.TransactionStorageStub(self._channel)

    def terminate(self):
        self.close()
        super().terminate()

    def run(self):
        """internal method for Process interface, do not run directly"""
        # TODO: some tuning with benchmarks
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        store = self._store_constructor()
        servicer = TransactionStorageServicer(store)
        protos.add_TransactionStorageServicer_to_server(servicer, server)
        port = server.add_insecure_port('127.0.0.1:0')
        self._port_q.put(port)
        server.start()
        self._exit_q.get()
        # the above all blocks until _exit_q.put(None) or _exit_q closes
        server.stop(0)

    # TransactionStorageSync interface implementation:

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx, *, only_metadata=False):
        self._ensure_alive()

        # genesis txs and metadata are kept in memory
        if tx.is_genesis and only_metadata:
            return

        tx_proto = tx.to_proto(include_metadata=True)
        request = protos.SaveRequest(transaction=tx_proto, only_metadata=only_metadata)
        result = self._stub.Save(request)
        # TODO: verify result.saved

        # call super which adds to index if needed
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes):
        self._ensure_alive()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = self._stub.Exists(request)
        return result.exists

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes):
        from hathor.transaction import Transaction
        self._ensure_alive()
        request = protos.GetRequest(hash=hash_bytes, include_metadata=True)
        result = self._stub.Get(request)
        return Transaction.create_from_proto(result.transaction, storage=self)

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self):
        from hathor.transaction import Transaction
        self._ensure_alive()
        request = protos.ListRequest(include_metadata=True)
        result = self._stub.List(request)
        for tx_proto in result:
            yield Transaction.create_from_proto(tx_proto, storage=self)

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self):
        self._ensure_alive()
        request = protos.CountRequest()
        result = self._stub.Count(request)
        return result.count

    # TransactionStorageAsync interface implementation:

    @inlineCallbacks
    def save_transaction_deferred(self, tx, *, only_metadata=False):
        self._ensure_alive()
        raise NotImplementedError

        # call super which adds to index if needed
        yield super().save_transaction_deferred(tx)

    @inlineCallbacks
    def transaction_exists_deferred(self, hash_bytes):
        self._ensure_alive()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = yield Deferred.fromFuture(self._stub.Exists.future(request))
        return result.exists

    def get_transaction_deferred(self, hash_bytes):
        self._ensure_alive()
        raise NotImplementedError

    def get_all_transactions_deferred(self):
        self._ensure_alive()
        raise NotImplementedError

    def get_count_tx_blocks_deferred(self):
        self._ensure_alive()
        raise NotImplementedError


class TransactionStorageServicer(protos.TransactionStorageServicer):
    def __init__(self, transaction_storage):
        self.storage = transaction_storage

    def Exists(self, request, context):
        hash_bytes = request.hash
        exists = skip_warning(self.storage.transaction_exists)(hash_bytes)
        return protos.ExistsResult(exists=exists)

    def Get(self, request, context):
        hash_bytes = request.hash
        include_metadata = request.include_metadata

        tx = skip_warning(self.storage.get_transaction)(hash_bytes)
        if include_metadata:
            tx.get_metadata()
        else:
            del tx._metadata

        return protos.GetResult(transaction=tx.to_proto())

    def Save(self, request, context):
        from hathor.transaction import Transaction, TransactionMetadata

        tx_proto = request.transaction
        only_metadata = request.only_metadata

        result = protos.SaveResult(saved=False)

        tx = Transaction.create_from_proto(tx_proto, storage=self.storage)
        skip_warning(self.storage.save_transaction)(tx, only_metadata=only_metadata)
        result.saved = True

        return result

    def List(self, request, context):
        include_metadata = request.include_metadata

        for tx in skip_warning(self.storage.get_all_transactions)():
            if include_metadata:
                tx.get_metadata()
            else:
                del tx._metadata
            yield tx.to_proto()

    def Count(self, request, context):
        count = skip_warning(self.storage.get_count_tx_blocks)()
        return protos.CountResult(count=count)
