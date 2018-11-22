import os
import json
import hashlib
from concurrent import futures
from multiprocessing import Process, Queue

from twisted.logger import Logger
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.logger import Logger

from hathor.protos import wallet_pb2_grpc as protos
from hathor.exception import HathorError
from hathor.wallet.keypair import KeyPair
from hathor.wallet.exceptions import OutOfUnusedAddresses
from hathor.wallet import BaseWallet
from hathor.pubsub import HathorEvents
from hathor.crypto.util import get_public_key_bytes_compressed


class SubprocessNotAliveError(HathorError):
    pass


class SubprocessWallet(BaseWallet, Process):
    log = Logger()


    def __init__(self, wallet_constructor, directory='./', history_file='history.json', pubsub=None):
        """
        :param wallet_constructor: a callable that returns an instance of TransactionStorage
        :type wallet_constructor: :py:class:`typing.Callable[..., hathor.transaction.wallet.BaseWallet]`
        """
        Process.__init__(self)
        BaseWallet.__init__(self, directory=directory, history_file=history_file, pubsub=pubsub)
        self._wallet_constructor = wallet_constructor
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

    def _manually_initialize(self):
        self.start()

    # multiporcessing.Process interface implementation

    def start(self):
        super().start()
        port = self._port_q.get()
        self._channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self._stub = protos.WalletStub(self._channel)

    def terminate(self):
        self.close()
        super().terminate()

    def run(self):
        """internal method for Process interface, do not run directly"""
        # TODO: some tuning with benchmarks
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        wallet = self._wallet_constructor()
        wallet._manually_initialize()
        servicer = WalletServicer(wallet)
        protos.add_WalletServicer_to_server(servicer, server)
        port = server.add_insecure_port('127.0.0.1:0')
        self._port_q.put(port)
        server.start()
        self._exit_q.get()
        # the above all blocks until _exit_q.put(None) or _exit_q closes
        server.stop(0)

    # hathor.wallet.BaseWallet interface implementation

    def is_locked(self):
        self._ensure_alive()
        request = protos.IsLockedRequest()
        response = self._stub.IsLocked(request)
        return response.is_locked

    def get_unused_address(self, mark_as_used=True):
        self._ensure_alive()
        request = protos.GetUnusedAddressRequest(mark_as_unused=mark_as_unused)
        response = self._stub.GetUnusedAddress(request)
        return response.address58

    def tokens_received(self, address58):
        self._ensure_alive()
        request = protos.TokensReceivedRequest(address58=address58)
        self._stub.TokensReceived(request)

    def get_private_key(self, address58):
        self._ensure_alive()
        request = protos.GetPrivateKeyRequest(address58=address58)
        response = self._stub.GetPrivateKey(request)
        return response.private_key

    def get_input_aux_data(self, data_to_sign, private_key):
        self._ensure_alive()
        request = protos.GetInputAuxData(data_to_sign=data_to_sign, private_key=private_key)
        response = self._stub.GetInputAuxData(request)
        return response.public_key, response.signature


class WalletServicer(protos.WalletServicer):
    def __init__(self, wallet):
        self.wallet = wallet

    def IsLocked(self, request, context):
        is_locked = self.wallet.is_locked()
        return protos.IsLockedResponse(is_locked=is_locked)

    def GetUnusedAddress(self, request, context):
        address58 = self.wallet.get_unused_address(mark_as_used=request.mark_as_used)
        return protos.GetUnusedAddressResponse(address58=address58)

    def TokensReceived(self, request, context):
        self.wallet.tokens_received(address=request.address58)
        return protos.TokensReceivedResponse()

    def GetPrivateKey(self, request, context):
        private_key = self.wallet.get_private_key(address=request.address58)
        # private_key = b'\0\0\0\0' + pycoin_key.serialize()
        return protos.GetPrivateKeyResponse(private_key=private_key)

    def GetInputAuxData(self, request, context):
        data_to_sign = request.data_to_sign
        private_key = request.private_key
        # private_key = BIP32Node.deserialize(private_key) # doesn't work like this
        public_key, signature = self.wallet.get_input_aux_data(data_to_sign, private_key)
        return protos.GetInputAuxData(public_key=public_key, signature=signature)
