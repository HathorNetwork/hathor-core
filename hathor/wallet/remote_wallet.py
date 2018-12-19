from hathor import protos
from hathor.wallet.base_wallet import IWallet
from hathor.grpc_util import StubConnect, convert_grpc_exceptions, convert_hathor_exceptions


class RemoteWalletFactory:
    def __init__(self, wallet_port, _remote_clock_factory=None):
        self._wallet_port = wallet_port
        self._remote_clock_factory = _remote_clock_factory

    def __call__(self):
        remote_wallet = RemoteWallet()
        remote_wallet.connect_to(self._wallet_port)
        if self._remote_clock_factory is not None:
            remote_wallet.clock = self._remote_clock_factory()
        else:
            remote_wallet.clock = None
        return remote_wallet


class RemoteWallet(StubConnect, IWallet):
    @classmethod
    def get_stub_class(cls):
        return protos.WalletStub

    @convert_grpc_exceptions
    def get_unused_address(self, mark_as_used=True):
        self._check_connection()
        request = protos.GetUnusedAddressRequest(mark_as_used=mark_as_used)
        response = self._stub.GetUnusedAddress(request)
        return response.address

    def get_unused_address_bytes(self, mark_as_used=True):
        address_str = self.get_unused_address(mark_as_used)
        return self.decode_address(address_str)

    @convert_grpc_exceptions
    def on_new_tx(self, tx):
        self._check_connection()
        request = protos.OnNewTxRequest(tx=tx.to_proto())
        self._stub.OnNewTx(request)


class RemoteWalletServicer(protos.WalletServicer):
    def __init__(self, wallet, tx_storage):
        self.wallet = wallet
        self.tx_storage = tx_storage

    @convert_hathor_exceptions
    def GetUnusedAddress(self, request, context):
        mark_as_used = request.mark_as_used
        address = self.wallet.get_unused_address(mark_as_used)
        return protos.GetUnusedAddressResponse(address=address)

    @convert_hathor_exceptions
    def OnNewTxRequest(self, request, context):
        from hathor.transaction import tx_or_block_from_proto
        tx = tx_or_block_from_proto(request.tx, storage=self.tx_storage)
        self.wallet.on_new_tx(tx)
        return protos.OnNewTxResponse()
