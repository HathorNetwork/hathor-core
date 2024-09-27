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
from typing import Any, Callable, NamedTuple, TypeVar

from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from typing_extensions import Self, override

from hathor.reactor import ReactorProtocol, initialize_global_reactor
from hathor.transaction.util import bytes_to_int, int_to_bytes

POLLING_INTERVAL: float = 0.001
MESSAGE_SEPARATOR: bytes = b' '
MAX_MESSAGE_ID: int = 2**64-1

ClientT = TypeVar('ClientT', bound='IpcClient')


def connect(
    *,
    main_reactor: ReactorProtocol,
    main: tuple[type[ClientT], type[IpcServer]],
    subprocess: tuple[type[IpcClient], type[IpcServer]],
    main_server_dependencies_builder: Callable[[IpcClient], dict[str, Any]],
    subprocess_server_dependencies_builder: Callable[[IpcClient], dict[str, Any]],
    subprocess_name: str,
) -> ClientT:
    main_client_conn: Connection
    main_server_conn: Connection
    subprocess_client_conn: Connection
    subprocess_server_conn: Connection
    main_client_conn, subprocess_server_conn = Pipe()
    subprocess_client_conn, main_server_conn = Pipe()

    main_server_message_id = multiprocessing.Value('L', 0)
    subprocess_server_message_id = multiprocessing.Value('L', 0)

    main_client_class, main_server_class = main
    subprocess_client_class, subprocess_server_class = subprocess

    main_client = _create_ipc_pair(
        reactor=main_reactor,
        name='main',
        client=(main_client_class, main_client_conn, subprocess_server_message_id),
        server=(main_server_class, main_server_conn, main_server_message_id),
        server_dependencies_builder=main_server_dependencies_builder,
    )

    process = Process(
        name=subprocess_name,
        target=_run_subprocess,
        kwargs=dict(
            name=subprocess_name,
            client=(subprocess_client_class, subprocess_client_conn, main_server_message_id),
            server=(subprocess_server_class, subprocess_server_conn, subprocess_server_message_id),
            server_dependencies_builder=subprocess_server_dependencies_builder,
        ),
    )
    process.start()

    return main_client


def _run_subprocess(
    *,
    name: str,
    client: tuple[type[IpcClient], Connection, Synchronized],
    server: tuple[type[IpcServer], Connection, Synchronized],
    server_dependencies_builder: Callable[[IpcClient], dict[str, Any]]
) -> None:
    subprocess_reactor = initialize_global_reactor()
    _create_ipc_pair(
        reactor=subprocess_reactor,
        name=name,
        client=client,
        server=server,
        server_dependencies_builder=server_dependencies_builder,
    )
    subprocess_reactor.run()


def _create_ipc_pair(
    *,
    reactor: ReactorProtocol,
    name: str,
    client: tuple[type[ClientT], Connection, Synchronized],
    server: tuple[type[IpcServer], Connection, Synchronized],
    server_dependencies_builder: Callable[[IpcClient], dict[str, Any]]
) -> ClientT:
    client_class, client_conn, client_message_id = client
    server_class, server_conn, server_message_id = server
    ipc_client = client_class(
        reactor=reactor,
        name=f'client({name})',
        conn=client_conn,
        message_id=client_message_id,
    )
    ipc_server = server_class(
        reactor=reactor,
        name=f'server({name})',
        conn=server_conn,
        message_id=server_message_id,
        **server_dependencies_builder(ipc_client)
    )

    ipc_client.start_listening()
    ipc_server.start_listening()
    return ipc_client


class _Message(NamedTuple):
    id: int
    data: bytes

    def serialize(self) -> bytes:
        return int_to_bytes(self.id, size=8) + MESSAGE_SEPARATOR + self.data

    @classmethod
    def deserialize(cls, data: bytes) -> Self:
        id_, separator, data = data.partition(MESSAGE_SEPARATOR)
        assert separator == MESSAGE_SEPARATOR
        return cls(
            id=bytes_to_int(id_),
            data=data,
        )


class _AbstractIpcConnection(ABC):
    __slots__ = (
        '_name',
        '_conn',
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
        message_id: Synchronized,
    ) -> None:
        self._name = name
        self._conn = conn
        self._message_id = message_id
        self._poll_lc = LoopingCall(self._safe_poll)
        self._poll_lc.clock = reactor
        self._pending_calls: dict[int, Deferred[bytes]] = {}

    def start_listening(self) -> None:
        self._poll_lc.start(POLLING_INTERVAL, now=False)

    def _send_message(self, data: bytes, request_id: int | None = None) -> _Message:
        message_id = self._get_new_message_id() if request_id is None else request_id
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
        self._handle_message(message)

    @abstractmethod
    def _handle_message(self, message: _Message) -> None:
        raise NotImplementedError


# sends requests and receive responses
class IpcClient(_AbstractIpcConnection):
    __slots__ = ('_pending_calls',)

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        name: str,
        conn: Connection,
        message_id: Synchronized,
    ) -> None:
        super().__init__(reactor=reactor, name=name, conn=conn, message_id=message_id)
        self._pending_calls: dict[int, Deferred[bytes]] = {}

    def call(self, request: bytes) -> Deferred[bytes]:
        message = self._send_message(request)
        deferred: Deferred[bytes] = Deferred()
        self._pending_calls[message.id] = deferred
        return deferred

    @override
    def _handle_message(self, message: _Message) -> None:
        pending_call = self._pending_calls.pop(message.id, None)
        assert pending_call is not None, f'unexpected message: {message}'
        # print(f'res({self._name}): ', message.data)
        pending_call.callback(message.data)


# receives requests and sends responses
class IpcServer(_AbstractIpcConnection):
    __slots__ = ()

    @override
    def _handle_message(self, message: _Message) -> None:
        # print(f'req({self._name}): ', message.data)
        coro = self.handle_request(message.data)
        deferred = Deferred.fromCoroutine(coro)
        deferred.addCallback(lambda response: self._send_message(response, request_id=message.id))

    @abstractmethod
    async def handle_request(self, request: bytes) -> bytes:
        raise NotImplementedError
