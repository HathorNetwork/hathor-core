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

import multiprocessing
from abc import ABC, abstractmethod
from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection
from multiprocessing.sharedctypes import Synchronized
from typing import Generic, NamedTuple, TypeVar

from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from typing_extensions import Self

from hathor.reactor import ReactorProtocol, initialize_global_reactor
from hathor.transaction.util import int_to_bytes, bytes_to_int

POLLING_INTERVAL: float = 0.001
MESSAGE_SEPARATOR: bytes = b' '
MAX_MESSAGE_ID: int = 2**64-1

T = TypeVar('T')


class IpcInterface(ABC, Generic[T]):
    __slots__ = ('_ipc_conn',)

    def __init__(self) -> None:
        self._ipc_conn: IpcConnection[T] | None = None

    @property
    def ipc_conn(self) -> IpcConnection[T]:
        assert self._ipc_conn is not None
        return self._ipc_conn

    @ipc_conn.setter
    def ipc_conn(self, ipc_conn: IpcConnection[T]) -> None:
        assert self._ipc_conn is None
        self._ipc_conn = ipc_conn

    @abstractmethod
    async def handle_request(self, request: T) -> T:
        raise NotImplementedError

    @abstractmethod
    def serialize(self, content: T) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, data: bytes) -> T:
        raise NotImplementedError


class _Message(NamedTuple):
    id: int
    data: bytes

    def serialize(self) -> bytes:
        return int_to_bytes(self.id, size=8) + MESSAGE_SEPARATOR + self.data

    @classmethod
    def deserialize(cls, data: bytes) -> Self:
        id_, separator, data = data.partition(MESSAGE_SEPARATOR)
        assert separator == MESSAGE_SEPARATOR
        return _Message(
            id=bytes_to_int(id_),
            data=data,
        )


class IpcConnection(Generic[T]):
    __slots__ = (
        '_name',
        '_conn',
        '_interface',
        '_message_id',
        '_poll_lc',
        '_pending_calls',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        name: str,
        conn: Connection,
        interface: IpcInterface[T],
        message_id: Synchronized,
    ) -> None:
        self._name = name
        self._conn = conn
        self._interface = interface
        self._message_id = message_id
        self._poll_lc = LoopingCall(self._safe_poll)
        self._poll_lc.clock = reactor
        self._pending_calls: dict[int, Deferred[T]] = {}

        self._interface.ipc_conn = self

    def _start_listening(self) -> None:
        self._poll_lc.start(POLLING_INTERVAL, now=False)

    @classmethod
    def fork(
        cls,
        *,
        main_reactor: ReactorProtocol,
        main_interface: IpcInterface,
        subprocess_interface: IpcInterface,
        subprocess_name: str,
    ) -> Self:
        conn1: Connection
        conn2: Connection
        conn1, conn2 = Pipe()
        message_id = multiprocessing.Value('L', 0)

        subprocess = Process(
            name=subprocess_name,
            target=cls._run_subprocess,
            kwargs=dict(name=subprocess_name, conn=conn2, interface=subprocess_interface, message_id=message_id),
        )
        subprocess.start()

        main_ipc_conn = cls(reactor=main_reactor, name='main', conn=conn1, message_id=message_id, interface=main_interface)
        main_ipc_conn._start_listening()
        return main_ipc_conn

    @classmethod
    def _run_subprocess(
        cls,
        *,
        name: str,
        conn: Connection,
        interface: IpcInterface,
        message_id: Synchronized,
    ) -> None:
        subprocess_reactor = initialize_global_reactor()
        subprocess_ipc_conn = cls(reactor=subprocess_reactor, name=name, conn=conn, interface=interface, message_id=message_id)
        subprocess_ipc_conn._start_listening()
        subprocess_reactor.run()

    def call(self, request: T) -> Deferred[T]:
        message = self._send_message(request)
        deferred: Deferred[T] = Deferred()
        self._pending_calls[message.id] = deferred
        return deferred

    def _send_message(self, content: T, request_id: int | None = None) -> _Message:
        message_id = self._get_new_message_id() if request_id is None else request_id
        data = self._interface.serialize(content)
        message = _Message(id=message_id, data=data)
        self._conn.send_bytes(message.serialize())
        return message

    def _get_new_message_id(self) -> int:
        with self._message_id.get_lock():
            message_id = self._message_id.value
            assert message_id < MAX_MESSAGE_ID
            self._message_id.value += 1
            return message_id

    def _safe_poll(self) -> None:
        try:
            self._unsafe_poll()
        except Exception as e:
            print('error', e)

    def _unsafe_poll(self) -> None:
        if not self._conn.poll():
            return

        message_bytes = self._conn.recv_bytes()
        message = _Message.deserialize(message_bytes)
        message_content = self._interface.deserialize(message.data)

        if pending_call := self._pending_calls.pop(message.id, None):
            # The received message is a response for one of our own requests
            # print(f'res({self._name}): {message_data}')
            pending_call.callback(message_content)
            return

        # The received message is a new request
        # print(f'req({self._name}): {message_data}')
        coro = self._interface.handle_request(message_content)
        deferred = Deferred.fromCoroutine(coro)
        deferred.addCallback(lambda response: self._send_message(response, request_id=message.id))
