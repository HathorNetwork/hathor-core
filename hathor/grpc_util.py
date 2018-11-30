import grpc

from abc import ABC, abstractclassmethod

from hathor.exception import HathorError
from hathor.transaction.storage.exceptions import TransactionDoesNotExist


class RemoteCommunicationError(HathorError):
    pass


class NotConnectedError(HathorError):
    pass


class StubConnect(ABC):
    """Mixin class for connecting stub channel and checking connection on every call."""

    @abstractclassmethod
    def get_stub_class(cls):
        raise NotImplementedError

    def connect_to(self, port):
        cur_channel = getattr(self, '_channel', None)
        if cur_channel:
            cur_channel.close()
        self._channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        stub_class = self.get_stub_class()
        self._stub = stub_class(self._channel)

    def _check_connection(self):
        """raise error if not connected"""
        if not getattr(self, '_channel', None):
            raise NotConnectedError


def convert_grpc_exceptions(func):
    """Decorator to catch and conver grpc excpetions for hathor expections.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() is grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_grpc_exceptions_generator(func):
    """Decorator to catch and conver grpc excpetions for hathor expections. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            yield from func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() is grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_hathor_exceptions(func):
    """Decorator to annotate better details and codes on the grpc context for known exceptions.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self, request, context):
        try:
            return func(self, request, context)
        except TransactionDoesNotExist:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Transaction does not exist.')
            raise

    return wrapper


def convert_hathor_exceptions_generator(func):
    """Decorator to annotate better details and codes on the grpc context for known exceptions. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self, request, context):
        try:
            yield from func(self, request, context)
        except TransactionDoesNotExist:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Transaction does not exist.')
            raise

    return wrapper
