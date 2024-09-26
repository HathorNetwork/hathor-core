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

import multiprocessing
from abc import ABC, abstractmethod
from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection
from multiprocessing.sharedctypes import Synchronized
from typing import Callable, Coroutine, Generic, NamedTuple, TypeVar

from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from typing_extensions import Self

from hathor.reactor import ReactorProtocol, initialize_global_reactor

POLLING_INTERVAL: float = 0.001

T = TypeVar('T')


class ProcessRPCHandler(ABC, Generic[T]):
    @abstractmethod
    async def handle_request(self, request: T) -> T:
        raise NotImplementedError

    @abstractmethod
    def serialize(self, message: T) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, data: bytes) -> T:
        raise NotImplementedError


class _Message(NamedTuple):
    id: int
    data: bytes


class ProcessRPC(Generic[T]):
    __slots__ = (
        '_name',
        '_conn',
        '_message_id',
        '_handler',
        '_poll_lc',
        '_pending_calls',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        name: str,
        conn: Connection,
        message_id: Synchronized,
        handler: ProcessRPCHandler[T]
    ) -> None:
        self._name = name
        self._conn = conn
        self._message_id = message_id
        self._handler = handler
        self._poll_lc = LoopingCall(self._safe_poll)
        self._poll_lc.clock = reactor
        self._pending_calls: dict[int, Deferred[T]] = {}

        self._poll_lc.start(POLLING_INTERVAL, now=False)

    @classmethod
    def fork(
        cls,
        *,
        main_reactor: ReactorProtocol,
        target: Callable[[Self], Coroutine[Deferred[None], None, None]],
        main_handler: ProcessRPCHandler,
        subprocess_handler: ProcessRPCHandler,
        subprocess_name: str,
    ) -> Self:
        conn1: Connection
        conn2: Connection
        conn1, conn2 = Pipe()
        message_id = multiprocessing.Value('i', 0)
        subprocess = Process(
            target=cls._run_subprocess,
            kwargs=dict(
                target=target, name=subprocess_name, conn=conn2, message_id=message_id, handler=subprocess_handler
            ),
            name=subprocess_name,
        )
        subprocess.start()
        main_rpc = cls(reactor=main_reactor, name='main', conn=conn1, message_id=message_id, handler=main_handler)
        return main_rpc

    @classmethod
    def _run_subprocess(
        cls,
        *,
        target: Callable[[Self], Coroutine[Deferred[None], None, None]],
        name: str,
        conn: Connection,
        message_id: Synchronized,
        handler: ProcessRPCHandler,
    ) -> None:
        subprocess_reactor = initialize_global_reactor()
        subprocess_rpc = cls(reactor=subprocess_reactor, name=name, conn=conn, message_id=message_id, handler=handler)
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=8090, stdoutToServer=True, stderrToServer=True)
        subprocess_reactor.callWhenRunning(lambda: Deferred.fromCoroutine(target(subprocess_rpc)))
        subprocess_reactor.run()

    def call(self, request: T) -> Deferred[T]:
        message = self._send_message(request)
        deferred: Deferred[T] = Deferred()
        self._pending_calls[message.id] = deferred
        return deferred

    def _safe_poll(self) -> None:
        try:
            self._unsafe_poll()
        except Exception as e:
            print('error', e)

    def _unsafe_poll(self) -> None:
        if not self._conn.poll():
            return

        message = self._conn.recv()
        assert isinstance(message, _Message)
        message_data = self._handler.deserialize(message.data)

        if pending_call := self._pending_calls.pop(message.id, None):
            # The received message is a response for one of our own requests
            # print(f'res({self._name}): {message_data}')
            pending_call.callback(message_data)
            return

        # The received message is a request
        # print(f'req({self._name}): {message_data}')
        deferred = Deferred.fromCoroutine(self._handler.handle_request(message_data))
        deferred.addCallback(lambda response: self._send_message(response, request_id=message.id))

    def _send_message(self, data: T, request_id: int | None = None) -> _Message:
        message_id = request_id
        if message_id is None:
            with self._message_id.get_lock():
                message_id = self._message_id.value
                self._message_id.value += 1

        message = _Message(id=message_id, data=self._handler.serialize(data))
        self._conn.send(message)
        return message
