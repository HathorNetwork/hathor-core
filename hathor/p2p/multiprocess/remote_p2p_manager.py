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
from typing import Any, TYPE_CHECKING

import zmq
from twisted.internet.task import LoopingCall

from hathor.reactor import ReactorProtocol
from structlog import get_logger

if TYPE_CHECKING:
    from hathor.p2p.manager import ConnectionsManager


logger = get_logger()


@dataclass(slots=True, kw_only=True, frozen=True)
class IpcRequest:
    method: str
    args: Any
    kwargs: Any


@dataclass(slots=True, frozen=True)
class IpcError:
    exception: Exception


class RemoteP2PManagerServer:
    __slots__ = ('log', '_p2p_manager', '_socket', '_lc')

    def __init__(self, *, reactor: ReactorProtocol, p2p_manager: ConnectionsManager) -> None:
        self.log = logger.new()
        self._p2p_manager = p2p_manager
        context = zmq.Context()
        self._socket = context.socket(zmq.REP)
        self._lc = LoopingCall(self._safe_run)
        self._lc.clock = reactor

    def start(self) -> None:
        self._socket.bind(f'ipc:///tmp/p2p_manager.sock')  # TODO: addr
        self._lc.start(0.1)

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
            method = getattr(self._p2p_manager, request.method)
            result = method(*request.args, **request.kwargs)
        except Exception as e:
            self.log.exception('error when processing IPC request', request=request)
            self._socket.send_pyobj(IpcError(e))
            return

        self.log.debug('sending IPC response', response=result)
        self._socket.send_pyobj(result)


class RemoteP2PManagerClient:
    __slots__ = ('log', '_socket',)

    def __init__(self) -> None:
        self.log = logger.new()
        context = zmq.Context()
        self._socket = context.socket(zmq.REQ)
        self._socket.connect(f'ipc:///tmp/p2p_manager.sock')  # TODO: addr

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
