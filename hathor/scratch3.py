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
import time
from typing import Any

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from typing_extensions import override

from hathor.multiprocess import ipc
from hathor.multiprocess.ipc import IpcClient, IpcServer
from hathor.reactor import ReactorProtocol, initialize_global_reactor


class HathorProtocol:
    __slots__ = ('_client',)

    def __init__(self, client: SubprocessIpcClient) -> None:
        self._client = client

    async def do_something(self, data: bytes) -> None:
        print('printing storage data from HathorProtocol: ', await self._client.read_storage(), os.getpid())
        time.sleep(5)
        await self._client.save_storage(data)
        await self._client.send_line(b'some line ' + data)


class SubprocessIpcClient(IpcClient):
    def read_storage(self) -> Deferred[bytes]:
        return self.call(b'read_storage')

    def save_storage(self, data: bytes) -> Deferred[bytes]:
        return self.call(b'save_storage ' + data)

    def send_line(self, data: bytes) -> Deferred[bytes]:
        return self.call(b'send_line ' + data)


class SubprocessIpcServer(IpcServer):
    __slots__ = ('_protocol',)

    def __init__(self, protocol: HathorProtocol, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._protocol = protocol

    @override
    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        assert cmd == b'do_something', request
        await self._protocol.do_something(data)
        return b'success'


class MainIpcClient(IpcClient):
    def do_something(self, data: bytes) -> Deferred[bytes]:
        return self.call(b'do_something ' + data)


class MainIpcServer(IpcServer):
    __slots__ = ('manager', '_line_receiver')

    def __init__(self, manager: HathorManager, line_receiver: IpcLineReceiver, **kwargs: Any) -> None:
        super().__init__(**kwargs)
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
        port = getattr(addr, 'port')
        main_client = ipc.connect(
            main_reactor=self.reactor,
            main=(MainIpcClient, MainIpcServer),
            subprocess=(SubprocessIpcClient, SubprocessIpcServer),
            subprocess_name=str(port),
            main_server_dependencies_builder=lambda _: dict(self.manager, ),
            subprocess_server_dependencies_builder=lambda client: {},
        )
        line_receiver = IpcLineReceiver(main_client)
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
