from twisted.logger import Logger

from hathor import protos
from hathor.manager import IManager
from hathor.grpc_util import StubConnect, convert_grpc_exceptions, convert_hathor_exceptions


class RemoteManagerFactory:
    def __init__(self, manager_port, tx_storage_factory):
        self._manager_port = manager_port
        self._tx_storage_factory = tx_storage_factory

    def __call__(self):
        remote_manager = RemoteManager()
        remote_manager.connect_to(self._manager_port)
        remote_manager.tx_storage = self._tx_storage_factory()
        return remote_manager


class RemoteManager(StubConnect, IManager):
    """Connects to a Storage API Server at given port and exposes standard storage interface.
    """
    log = Logger()

    @classmethod
    def get_stub_class(cls):
        return protos.HathorManagerStub

    @convert_grpc_exceptions
    def get_new_tx_parents(self, timestamp=None):
        self._check_connection()
        if isinstance(timestamp, float):
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.GetNewTxParentsRequest(timestamp=timestamp)
        result = self._stub.GetNewTxParents(request)
        return list(result.parent_hashes)

    @convert_grpc_exceptions
    def minimum_tx_weight(self, tx):
        self._check_connection()
        request = protos.MinimumTxWeightRequest(tx=tx.to_proto())
        result = self._stub.MinimumTxWeight(request)
        return result.weight

    @convert_grpc_exceptions
    def propagate_tx(self, tx):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.PropagateTxRequest(tx=tx.to_proto())
        result = self._stub.PropagateTx(request)
        tx_re = tx_or_block_from_proto(result.tx)
        if hasattr(tx_re, '_metadata'):
            tx._metadata = tx_re._metadata
        return result.propagated


class HathorManagerServicer(protos.HathorManagerServicer):
    def __init__(self, hathor_manager):
        self.manager = hathor_manager

    @convert_hathor_exceptions
    def GetNewTxParents(self, request, context):
        timestamp = request.timestamp
        parent_hashes = self.manager.get_new_tx_parents(timestamp)
        return protos.GetNewTxParentsResponse(parent_hashes=parent_hashes)

    @convert_hathor_exceptions
    def MinimumTxWeight(self, request, context):
        from hathor.transaction import tx_or_block_from_proto

        tx = tx_or_block_from_proto(request.tx, storage=self.manager.tx_storage)
        weight = self.manager.minimum_tx_weight(tx)
        return protos.MinimumTxWeightResponse(weight=weight)

    @convert_hathor_exceptions
    def PropagateTx(self, request, context):
        from hathor.transaction import tx_or_block_from_proto
        # tx = tx_or_block_from_proto(request.tx, storage=self.manager.tx_storage)
        tx = tx_or_block_from_proto(request.tx)
        propagated = self.manager.propagate_tx(tx)
        return protos.PropagateTxResponse(propagated=propagated, tx=tx.to_proto())
