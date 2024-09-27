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
from typing import Callable, NamedTuple, TypeVar

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
    main_client: IpcClient,
    main_server: IpcServer,
    subprocess_client_builder: Callable[[], ClientT],
    subprocess_server_builder: Callable[[ClientT], IpcServer],
    subprocess_name: str,
) -> None:
    main_client_conn: Connection
    main_server_conn: Connection
    subprocess_client_conn: Connection
    subprocess_server_conn: Connection
    main_client_conn, subprocess_server_conn = Pipe()
    subprocess_client_conn, main_server_conn = Pipe()

    main_server_message_id = multiprocessing.Value('L', 0)
    subprocess_server_message_id = multiprocessing.Value('L', 0)

    main_client_ipc = _create_ipc_pair(
        reactor=main_reactor,
        name='main',
        client_conn=main_client_conn,
        server_conn=main_server_conn,
        client_message_id=subprocess_server_message_id,
        server_message_id=main_server_message_id,
        ipc_server=main_server,
    )
    main_client.set_ipc_conn(main_client_ipc)

    subprocess = Process(
        name=subprocess_name,
        target=_run_subprocess,
        kwargs=dict(
            name=subprocess_name,
            client_conn=subprocess_client_conn,
            server_conn=subprocess_server_conn,
            client_message_id=main_server_message_id,
            server_message_id=subprocess_server_message_id,
            client_builder=subprocess_client_builder,
            server_builder=subprocess_server_builder,
        ),
    )
    subprocess.start()


def _run_subprocess(
    *,
    name: str,
    client_conn: Connection,
    server_conn: Connection,
    client_message_id: Synchronized,
    server_message_id: Synchronized,
    client_builder: Callable[[], ClientT],
    server_builder: Callable[[ClientT], IpcServer],
) -> None:
    subprocess_reactor = initialize_global_reactor()
    client = client_builder()
    server = server_builder(client)
    client_ipc = _create_ipc_pair(
        reactor=subprocess_reactor,
        name=name,
        client_conn=client_conn,
        server_conn=server_conn,
        client_message_id=client_message_id,
        server_message_id=server_message_id,
        ipc_server=server,
    )
    client.set_ipc_conn(client_ipc)
    subprocess_reactor.run()


def _create_ipc_pair(
    *,
    reactor: ReactorProtocol,
    name: str,
    client_conn: Connection,
    server_conn: Connection,
    client_message_id: Synchronized,
    server_message_id: Synchronized,
    ipc_server: IpcServer,
) -> _ClientIpcConnection:
    client = _ClientIpcConnection(
        reactor=reactor,
        name=f'client({name})',
        conn=client_conn,
        message_id=client_message_id,
    )
    server = _ServerIpcConnection(
        reactor=reactor,
        name=f'server({name})',
        conn=server_conn,
        message_id=server_message_id,
        server=ipc_server,
    )

    client.start_listening()
    server.start_listening()
    return client


class IpcClient(ABC):
    __slots__ = ('_ipc_conn',)

    def __init__(self) -> None:
        self._ipc_conn: _ClientIpcConnection | None = None

    def set_ipc_conn(self, ipc_conn: _ClientIpcConnection) -> None:
        assert self._ipc_conn is None
        self._ipc_conn = ipc_conn

    def _call(self, request: bytes) -> Deferred[bytes]:
        assert self._ipc_conn is not None
        return self._ipc_conn.call(request)


class IpcServer(ABC):
    @abstractmethod
    async def handle_request(self, request: bytes) -> bytes:
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
class _ClientIpcConnection(_AbstractIpcConnection):
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
class _ServerIpcConnection(_AbstractIpcConnection):
    __slots__ = ('_server',)

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        name: str,
        conn: Connection,
        message_id: Synchronized,
        server: IpcServer,
    ) -> None:
        super().__init__(reactor=reactor, name=name, conn=conn, message_id=message_id)
        self._server = server

    @override
    def _handle_message(self, message: _Message) -> None:
        # print(f'req({self._name}): ', message.data)
        coro = self._server.handle_request(message.data)
        deferred = Deferred.fromCoroutine(coro)
        deferred.addCallback(lambda response: self._send_message(response, request_id=message.id))
