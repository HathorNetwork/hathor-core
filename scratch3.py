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
import time

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from typing_extensions import Self

from hathor.multiprocess import ipc
from hathor.multiprocess.ipc import IpcServer, IpcClient
from hathor.reactor import initialize_global_reactor, ReactorProtocol


class HathorProtocol:
    __slots__ = ('_client',)

    def __init__(self, client: SubprocessIpcClient) -> None:
        self._client = client

    async def do_something(self, data: bytes) -> None:
        print('printing storage data from HathorProtocol: ', await self._client.read_storage(), os.getpid())
        time.sleep(5)
        await self._client.save_storage(data)
        await self._client.send_line(b'some line ' + data)


class SubprocessIpcServer(IpcServer):
    __slots__ = ('_protocol',)

    @classmethod
    def build(cls, client: SubprocessIpcClient) -> Self:
        protocol = HathorProtocol(client)
        return cls(protocol)

    def __init__(self, protocol: HathorProtocol) -> None:
        self._protocol = protocol

    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        assert cmd == b'do_something', request
        await self._protocol.do_something(data)
        return b'success'


class SubprocessIpcClient(IpcClient):
    def read_storage(self) -> Deferred[bytes]:
        return self._call(b'read_storage')

    def save_storage(self, data: bytes) -> Deferred[bytes]:
        return self._call(b'save_storage ' + data)

    def send_line(self, data: bytes) -> Deferred[bytes]:
        return self._call(b'send_line ' + data)


class MainIpcServer(IpcServer):
    __slots__ = ('manager', '_line_receiver')

    def __init__(self, manager: HathorManager, line_receiver: IpcLineReceiver) -> None:
        self.manager = manager
        self._line_receiver = line_receiver

    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        if cmd == b'read_storage':
            return self.manager.read_storage()
        elif cmd == b'save_storage':
            self.manager.save_storage(data)
            return b'success'
        elif cmd == b'send_line':
            self._line_receiver.sendLine(data)
            return b'success'
        raise AssertionError(request)


class MainIpcClient(IpcClient):
    def do_something(self, data: bytes) -> Deferred[bytes]:
        return self._call(b'do_something ' + data)


class IpcLineReceiver(LineReceiver):
    __slots__ = ('_client',)

    def __init__(self, client: MainIpcClient) -> None:
        self._client = client

    def lineReceived(self, data: bytes) -> None:
        self._client.do_something(data)


class IpcFactory(ServerFactory):
    def __init__(self, reactor: ReactorProtocol, manager: HathorManager) -> None:
        self.reactor = reactor
        self.manager = manager

    def buildProtocol(self, addr: IAddress) -> IpcLineReceiver:
        main_client = MainIpcClient()
        line_receiver = IpcLineReceiver(main_client)
        main_server = MainIpcServer(self.manager, line_receiver)
        ipc.connect(
            main_reactor=self.reactor,
            main_client=main_client,
            main_server=main_server,
            subprocess_client_builder=SubprocessIpcClient,
            subprocess_server_builder=SubprocessIpcServer.build,
            subprocess_name=str(addr.port)
        )
        return line_receiver


class HathorManager:
    def __init__(self, *, storage: bytes):
        self._storage = storage

    def read_storage(self) -> bytes:
        return self._storage

    def save_storage(self, data: bytes) -> None:
        print('printing from HathorManager.save_storage: ', data, os.getpid())


def main():
    port = 8080
    reactor = initialize_global_reactor()
    manager = HathorManager(storage=b'manager storage')
    factory = IpcFactory(reactor, manager)
    reactor.listenTCP(port, factory)
    print(f'Server running on port {port}')
    reactor.run()


if __name__ == '__main__':
    main()
