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

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

import zmq
from structlog import get_logger
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.task import LoopingCall

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.protocol import HathorProtocol
from hathor.reactor import ReactorProtocol
from hathor.verification.verification_service import VerificationService
from hathor.vertex_handler import VertexHandler

# TODO: Move out of p2p package


logger = get_logger()

SOCKET_TIMEOUT = 5.0
IPC_SERVER_LOOP_INTERVAL = 0.0


class IpcProxyType(Enum):
    P2P_MANAGER = ConnectionsManager
    P2P_CONNECTION = HathorProtocol
    VERTEX_HANDLER = VertexHandler
    VERIFICATION_SERVICE = VerificationService

    def addr(self) -> str:
        assert self is not IpcProxyType.P2P_CONNECTION  # TODO: Improve this addr handling.
        return f'ipc:///tmp/{self.name}.sock'


@dataclass(slots=True, kw_only=True, frozen=True)
class IpcRequest:
    method: str
    args: Any
    kwargs: Any


@dataclass(slots=True, frozen=True)
class IpcError:
    exception: Exception


class RemoteIpcServer:
    __slots__ = ('log', '_proxy_type', '_proxy_obj', '_socket', '_lc', '_addr')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        proxy_type: IpcProxyType,
        proxy_obj: Any,
        addr: IPv4Address | IPv6Address | None = None,
    ) -> None:
        assert isinstance(proxy_obj, proxy_type.value)
        self.log = logger.new(name=proxy_type.name, pid=os.getpid())
        self._proxy_type = proxy_type
        self._proxy_obj = proxy_obj
        self._addr = addr

        context = zmq.Context()
        self._socket = context.socket(zmq.REP)
        self._lc = LoopingCall(self._safe_run)
        self._lc.clock = reactor

    def start(self) -> None:
        from hathor.multiprocess.subprocess_wrapper import get_subprocess_protocol_server_addr
        # TODO: Improve addr handling.
        addr = get_subprocess_protocol_server_addr(self._addr) if self._addr else self._proxy_type.addr()
        self._socket.bind(addr)
        self._lc.start(IPC_SERVER_LOOP_INTERVAL)

    def stop(self) -> None:
        self._lc.stop()
        self._socket.close(linger=0)

    def _safe_run(self) -> None:
        try:
            self._unsafe_run()
        except Exception:
            self.log.exception('error in looping call')

    def _unsafe_run(self) -> None:
        try:
            request = self._socket.recv_pyobj(flags=zmq.NOBLOCK)
        except zmq.Again:
            return
        except Exception as e:
            self.log.exception('error when receiving IPC request')
            self._socket.send_pyobj(IpcError(e), flags=zmq.NOBLOCK)
            return

        self.log.debug('received IPC request', request=request)
        assert isinstance(request, IpcRequest)

        try:
            method = getattr(self._proxy_obj, request.method)
            result = method(*request.args, **request.kwargs)
        except Exception as e:
            self.log.exception('error when processing IPC request', request=request)
            self._socket.send_pyobj(IpcError(e), flags=zmq.NOBLOCK)
            return

        self._socket.send_pyobj(result, flags=zmq.NOBLOCK)


class RemoteIpcClient:
    __slots__ = ('log', '_socket', '_blocking')

    def __init__(self, *, proxy_type: IpcProxyType, blocking: bool = False, addr: str | None = None) -> None:
        self.log = logger.new(name=proxy_type.name, pid=os.getpid(), blocking=blocking)
        self._blocking = blocking

        context = zmq.Context()
        self._socket = context.socket(zmq.REQ)
        self._socket.connect(addr if addr else proxy_type.addr())  # TODO: Improve this addr handling.

    def stop(self) -> None:
        self._socket.close(linger=0)

    def __getattr__(self, name: str) -> Any:
        def call_remote(*args: Any, **kwargs: Any) -> Any:
            self.log.debug('sending IPC request', method=name, args=args, kwargs=kwargs)
            request = IpcRequest(method=name, args=args, kwargs=kwargs)
            response = self._send_request(request)
            self.log.debug('received IPC response', response=response)

            if isinstance(response, IpcError):
                raise response.exception

            return response

        return call_remote

    def _send_request(self, request: IpcRequest) -> Any:
        timeout = SOCKET_TIMEOUT if self._blocking else 0
        timeout = None
        _, wlist, _ = zmq.select([], [self._socket], [], timeout=timeout)
        timeout_message = 'timeout while {}. This is likely caused by a deadlock. Check tracebacks below'

        if not wlist:
            self.log.error(timeout_message.format('sending request'), request=request)
            raise TimeoutError

        assert wlist == [self._socket]
        self._socket.send_pyobj(request)

        rlist, _, _ = zmq.select([self._socket], [], [], timeout=timeout)
        if not rlist:
            self.log.error(timeout_message.format('receiving response'), request=request)
            raise TimeoutError

        assert rlist == [self._socket]
        return self._socket.recv_pyobj()
