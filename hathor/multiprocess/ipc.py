#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import inspect
import os
import typing
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar, assert_never, cast

import zmq
from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure
from typing_extensions import Self

from hathor.reactor import ReactorProtocol
from hathor.utils import pickle

logger = get_logger()

IPC_SERVER_PATH = '/tmp/hathor_ipc_server.sock'
IPC_POLLING_INTERVAL = 0.001  # seconds
IPC_BLOCKING_TIMEOUT = 1.0  # seconds

T = TypeVar('T')


@dataclass(slots=True, frozen=True, kw_only=True)
class _IpcResponse:
    request_id: str
    result: Any
    is_async: bool


@dataclass(slots=True, frozen=True, kw_only=True)
class _IpcRequest:
    service: str
    method: str
    args: Any
    kwargs: Any
    is_async: bool
    request_id: str = field(init=False, default_factory=lambda: str(uuid.uuid4()))

    def create_response(self, result: Any) -> _IpcResponse:
        return _IpcResponse(request_id=self.request_id, result=result, is_async=self.is_async)


@dataclass(slots=True, frozen=True, kw_only=True)
class _IpcMethod:
    callable: Callable[..., Any]
    is_async: bool


class IpcConnection:
    __slots__ = (
        'log',
        'reactor',
        '_context',
        '_socket',
        '_socket_addr',
        'server',
        '_services',
        '_lc',
        '_deferreds'
    )

    def __init__(self, *, reactor: ReactorProtocol, socket_path: str, server: bool = False) -> None:
        self.log = logger.new(pid=os.getpid())
        self.reactor = reactor
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.ROUTER if server else zmq.DEALER)
        self._socket_addr = f'ipc://{socket_path}'
        self.server = server
        self._services: dict[str, dict[str, _IpcMethod]] = defaultdict(dict)
        self._lc = LoopingCall(self._safe_run)  # TODO: Try to register a reader in the reactor instead of using LC
        self._lc.clock = reactor
        self._deferreds: dict[str, Deferred[Any]] = {}

    def register_service(self, obj: T, *, as_protocol: type[T]) -> Self:
        service_name = as_protocol.__name__
        if service_name in self._services:
            raise ValueError(f'service "{service_name}" is already registered')

        for method_name, _ in inspect.getmembers(as_protocol):
            if method_name.startswith('_'):
                continue

            method = getattr(obj, method_name, None)
            assert callable(method), f'method "{service_name}.{method_name}" is not callable: {method}'
            self._services[service_name][method_name] = _IpcMethod(callable=method, is_async=_is_async(method))

        return self

    def set_custom_identity(self, identity: str) -> Self:
        assert not self.server
        self._socket.setsockopt_string(zmq.IDENTITY, identity)
        return self

    def start(self) -> None:
        self.log.info('IPC connection starting', addr=self._socket_addr, server=self.server)
        connect_func = self._socket.bind if self.server else self._socket.connect
        connect_func(self._socket_addr)
        self._lc.start(IPC_POLLING_INTERVAL)

    def stop(self) -> None:
        self._lc.stop()
        self._socket.close(linger=0)
        self._context.term()

        for deferred in self._deferreds.values():
            assert not deferred.called
            deferred.cancel()

    async def _safe_run(self) -> None:
        try:
            await self._unsafe_run()
        except Exception:
            self.log.exception('error in looping call')

    async def _unsafe_run(self) -> None:
        try:
            message, client_id = self._recv_message()
        except zmq.Again:
            return
        await self._handle_message(message, client_id)

    async def _handle_message(self, message: _IpcRequest | _IpcResponse, client_id: bytes | str | None) -> None:
        match message:
            case _IpcRequest():
                await self._handle_request(request=message, client_id=client_id)
            case _IpcResponse():
                self._handle_response(response=message)
            case _:
                assert_never(message)

    async def _handle_request(self, *, request: _IpcRequest, client_id: bytes | str | None) -> None:
        self.log.debug('received IPC request', request=request, client_id=client_id)
        service = self._services.get(request.service)
        if service is None:
            self.log.error('IPC service not found', service=request.service)
            response = request.create_response(ValueError(f'service not found: {request.service}'))
            self._send_message(response, client_id)
            return

        method = service.get(request.method)
        if method is None:
            self.log.error('IPC method not found', service=request.service, method=request.method)
            response = request.create_response(ValueError(f'method not found: {request.method}'))
            self._send_message(response, client_id)
            return

        assert method.is_async == request.is_async
        try:
            result = method.callable(*request.args, **request.kwargs)
            if method.is_async:
                result = await result
        except Exception as e:
            self.log.exception('error when processing IPC request', request=request)
            response = request.create_response(e)
            self._send_message(response, client_id)
            return

        response = request.create_response(result)
        self.log.debug('sending IPC response', response=response)
        self._send_message(response, client_id)

    def _handle_response(self, *, response: _IpcResponse) -> None:
        if not response.is_async:
            return

        self.log.debug('received IPC response', response=response)
        deferred = self._deferreds.pop(response.request_id, None)

        if deferred is None or deferred.called:
            self.log.error('invalid deferred state', deferred=deferred, response=response)
            raise AssertionError

        if isinstance(response.result, Exception):
            deferred.errback(Failure(response.result))
            return

        deferred.callback(response.result)

    def _recv_message(self, *, blocking: bool = False) -> tuple[_IpcRequest | _IpcResponse, bytes | None]:
        multipart = self._socket.recv_multipart(flags=0 if blocking else zmq.NOBLOCK)
        client_id, message_data = multipart if self.server else (None, multipart[0])
        assert isinstance(message_data, bytes)
        message = pickle.loads(message_data)
        assert isinstance(message, (_IpcRequest, _IpcResponse))
        return message, client_id

    def _send_message(self, message: _IpcRequest | _IpcResponse, client_id: bytes | str | None) -> None:
        if isinstance(client_id, str):
            client_id = client_id.encode('utf-8')
        try:
            message_data = pickle.dumps(message)
        except Exception:
            self.log.exception('pickling error', message=message)
            return
        multipart = [client_id, message_data] if self.server else [message_data]
        self._socket.send_multipart(multipart, flags=zmq.NOBLOCK)

    def get_proxy(self, protocol: type[T], client_id: str | None = None) -> T:
        proxy = IpcClientProxy(protocol=protocol, conn=self, client_id=client_id)
        return cast(T, proxy)

    def call_blocking(self, request: _IpcRequest, *, client_id: str | None) -> _IpcResponse:
        assert not request.is_async
        self._send_message(request, client_id if client_id else None)
        remaining_time = IPC_BLOCKING_TIMEOUT

        while True:
            if remaining_time <= 0:
                self.log.error('timeout while waiting response', request=request)
                raise TimeoutError

            time_before = self.reactor.seconds()
            rlist, _, _ = zmq.select([self._socket], [], [], timeout=remaining_time)
            elapsed_time = self.reactor.seconds() - time_before
            remaining_time -= elapsed_time

            if not rlist:
                self.log.error('timeout while waiting response', request=request)
                raise TimeoutError

            assert rlist == [self._socket]
            message, msg_client_id = self._recv_message(blocking=True)

            if isinstance(message, _IpcResponse) and message.request_id == request.request_id:
                return message

            # TODO: call_coro_later
            self.reactor.callLater(0, lambda: Deferred.fromCoroutine(self._handle_message(message, client_id)))

    def call_async(self, request: _IpcRequest, *, client_id: str | None) -> Deferred[Any]:
        assert request.is_async
        assert request.request_id not in self._deferreds
        self._send_message(request, client_id)
        deferred: Deferred[Any] = Deferred()
        self._deferreds[request.request_id] = deferred
        return deferred


class IpcClientProxy:
    __slots__ = ('log', '_service', '_conn', '_client_id', '_methods')

    def __init__(self, *, protocol: type, conn: IpcConnection, client_id: str | None) -> None:
        if client_id:
            assert conn.server
        self.log = logger.new(pid=os.getpid())
        self._service = protocol.__name__
        self._methods = self._process_methods(protocol)
        self._conn = conn
        self._client_id = client_id

    @staticmethod
    def _process_methods(protocol: type) -> dict[str, bool]:
        methods = {}
        for method_name, _ in inspect.getmembers(protocol):
            if method_name.startswith('_'):
                continue

            method = getattr(protocol, method_name, None)
            assert callable(method), f'method "{method_name}" is not callable: {method}'
            methods[method_name] = _is_async(method)

        return methods

    def __getattr__(self, name: str) -> Any:
        is_async = self._methods.get(name)
        if is_async is None:
            raise TypeError(f'unknown method: {name}')

        def method_proxy(*args: Any, **kwargs: Any) -> Any:
            request = _IpcRequest(service=self._service, method=name, args=args, kwargs=kwargs, is_async=is_async)
            self.log.debug('sending IPC request', request=request)
            response: _IpcResponse | Deferred[Any]

            if is_async:
                response = self._conn.call_async(request, client_id=self._client_id)
                self.log.debug('received IPC response', response=response)
                return response

            response = self._conn.call_blocking(request, client_id=self._client_id)
            self.log.debug('received IPC response', response=response)
            if isinstance(response.result, Exception):
                raise response.result
            return response.result
        return method_proxy


def _is_async(func: Callable[..., Any]) -> bool:
    if inspect.iscoroutinefunction(func):
        return True

    annotations = inspect.get_annotations(func)
    if 'return' not in annotations:
        raise TypeError(f'function should be annotated: {func}')

    return_type = annotations['return']
    return Deferred in (return_type, typing.get_origin(return_type))
