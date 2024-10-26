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

from dataclasses import dataclass
from enum import Enum
from typing import Any

import zmq
from twisted.internet.task import LoopingCall

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.protocol import HathorProtocol
from hathor.reactor import ReactorProtocol
from structlog import get_logger

from hathor.verification.verification_service import VerificationService
from hathor.vertex_handler import VertexHandler

# TODO: Move out of p2p package


logger = get_logger()

IPC_SERVER_LOOP_INTERVAL = 0.01


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
    __slots__ = ('log', '_proxy_type', '_proxy_obj', '_socket', '_lc')

    def __init__(self, *, reactor: ReactorProtocol, proxy_type: IpcProxyType, proxy_obj: Any) -> None:
        assert isinstance(proxy_obj, proxy_type.value)
        self.log = logger.new(name=proxy_type.name)
        self._proxy_type = proxy_type
        self._proxy_obj = proxy_obj

        context = zmq.Context()
        self._socket = context.socket(zmq.REP)
        self._lc = LoopingCall(self._safe_run)
        self._lc.clock = reactor

    def start(self) -> None:
        addr = self._proxy_type.addr()
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
            self._socket.send_pyobj(IpcError(e))
            return

        self.log.debug('received IPC request', request=request)
        assert isinstance(request, IpcRequest)

        try:
            method = getattr(self._proxy_obj, request.method)
            result = method(*request.args, **request.kwargs)
        except Exception as e:
            self.log.exception('error when processing IPC request', request=request)
            self._socket.send_pyobj(IpcError(e))
            return

        self.log.debug('sending IPC response', response=result)
        self._socket.send_pyobj(result)


class RemoteIpcClient:
    __slots__ = ('log', '_socket')

    def __init__(self, *, proxy_type: IpcProxyType, addr: str | None = None) -> None:
        self.log = logger.new(name=proxy_type.name)

        context = zmq.Context()
        self._socket = context.socket(zmq.REQ)
        self._socket.connect(addr if addr else proxy_type.addr())  # TODO: Improve this addr handling.

    def stop(self) -> None:
        self._socket.close(linger=0)

    def __getattr__(self, name: str) -> Any:
        def call_remote(*args: Any, **kwargs: Any) -> Any:
            self.log.debug('sending IPC request', method=name, args=args, kwargs=kwargs)
            request = IpcRequest(method=name, args=args, kwargs=kwargs)
            self._socket.send_pyobj(request)
            response = self._socket.recv_pyobj()  # TODO: non-block
            self.log.debug('received IPC response', response=response)

            if isinstance(response, IpcError):
                raise response.exception

            return response

        return call_remote
