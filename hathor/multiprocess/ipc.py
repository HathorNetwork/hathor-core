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
from typing import Any, Callable, Coroutine, NamedTuple, TypeAlias, TypeVar, Union

from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from typing_extensions import Self

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
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
    subprocess_server_builder: Callable[[ReactorProtocol, HathorSettings, ClientT, dict[str, Any]], IpcServer],
    subprocess_server_args: dict[str, Any],
    subprocess_name: str,
) -> None:
    conn1: Connection
    conn2: Connection
    conn1, conn2 = Pipe()
    message_id = multiprocessing.Value('L', 0)

    # TODO: Assert this is the main process
    main_ipc_conn = _IpcConnection(
        reactor=main_reactor, name='main', conn=conn1, message_id=message_id, server=main_server
    )
    main_client.set_ipc_conn(main_ipc_conn)
    main_ipc_conn.start_listening()

    subprocess = Process(
        name=subprocess_name,
        target=_run_subprocess,
        kwargs=dict(
            name=subprocess_name,
            conn=conn2,
            client_builder=subprocess_client_builder,
            server_builder=subprocess_server_builder,
            server_args=subprocess_server_args,
            message_id=message_id,
        ),
    )
    subprocess.start()


def _run_subprocess(
    *,
    name: str,
    conn: Connection,
    client_builder: Callable[[], ClientT],
    server_builder: Callable[[ReactorProtocol, HathorSettings, ClientT, dict[str, Any]], IpcServer],
    server_args: dict[str, Any],
    message_id: Synchronized,
) -> None:
    subprocess_reactor = initialize_global_reactor()
    settings = get_global_settings()  # TODO: Check if this uses the correct env vars
    client = client_builder()
    server = server_builder(
        subprocess_reactor,
        settings,
        client,
        server_args,
    )
    subprocess_ipc_conn = _IpcConnection(
        reactor=subprocess_reactor, name=name, conn=conn, server=server, message_id=message_id
    )
    client.set_ipc_conn(subprocess_ipc_conn)
    subprocess_ipc_conn.start_listening()
    subprocess_reactor.run()


IpcCommand: TypeAlias = Union[
    Callable[[bytes], Coroutine[Deferred[bytes], Any, bytes]],
    Callable[[bytes], Coroutine[Deferred[None], Any, None]],
]


class IpcServer(ABC):
    @abstractmethod
    def get_cmd_map(self) -> dict[bytes, IpcCommand]:
        raise NotImplementedError

    async def handle_request(self, request: bytes) -> bytes:
        cmd_name, _, data = request.partition(MESSAGE_SEPARATOR)
        cmd_map = self.get_cmd_map()
        cmd = cmd_map.get(cmd_name)
        assert cmd is not None, cmd_name
        result = await cmd(data)
        return result if result is not None else b'success'


class IpcClient(ABC):
    __slots__ = ('_ipc_conn',)

    def __init__(self) -> None:
        self._ipc_conn: _IpcConnection | None = None

    def set_ipc_conn(self, ipc_conn: _IpcConnection) -> None:
        assert self._ipc_conn is None
        self._ipc_conn = ipc_conn

    def call(self, cmd: bytes, request: bytes | None = None) -> Deferred[bytes]:
        assert self._ipc_conn is not None
        return self._ipc_conn.call(cmd, request)


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


class _IpcConnection:
    __slots__ = (
        '_name',
        '_conn',
        '_server',
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
        server: IpcServer,
        message_id: Synchronized,
    ) -> None:
        self._name = name
        self._conn = conn
        self._server = server
        self._message_id = message_id
        self._poll_lc = LoopingCall(self._safe_poll)
        self._poll_lc.clock = reactor
        self._pending_calls: dict[int, Deferred[bytes]] = {}

    def start_listening(self) -> None:
        self._poll_lc.start(POLLING_INTERVAL, now=False)

    def call(self, cmd: bytes, request: bytes | None) -> Deferred[bytes]:
        data = cmd if request is None else cmd + MESSAGE_SEPARATOR + request
        message_id = self._send_message(data)
        deferred: Deferred[bytes] = Deferred()
        self._pending_calls[message_id] = deferred
        return deferred

    def _send_message(self, data: bytes, request_id: int | None = None) -> int:
        message_id = self._get_new_message_id() if request_id is None else request_id
        message = _Message(id=message_id, data=data)
        self._conn.send_bytes(message.serialize())
        return message.id

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

        if pending_call := self._pending_calls.pop(message.id, None):
            # The received message is a response for one of our own requests
            # print(f'res({self._name}): {message_data}')
            pending_call.callback(message.data)
            return

        # The received message is a new request
        # print(f'req({self._name}): {message_data}')
        coro = self._server.handle_request(message.data)
        deferred = Deferred.fromCoroutine(coro)
        deferred.addCallback(lambda response: self._send_message(response, request_id=message.id))
