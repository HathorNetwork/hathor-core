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

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

from hathor.multiprocess.process_rpc import IpcConnection, IpcInterface
from hathor.reactor import initialize_global_reactor, ReactorProtocol


class HathorProtocol:
    def __init__(self, interface: SubprocessInterface) -> None:
        self._interface = interface

    async def do_something(self, data: bytes) -> None:
        print('printing HathorManager data from HathorProtocol: ', await self._interface.get_data(), os.getpid())
        time.sleep(5)
        await self._interface.send_data(data)


class SubprocessInterface(IpcInterface[bytes]):
    __slots__ = ('_protocol',)

    def __init__(self) -> None:
        super().__init__()
        self._protocol = HathorProtocol(self)

    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        assert cmd == b'do_something', request
        await self._protocol.do_something(data)
        return b'success'

    def serialize(self, message: bytes) -> bytes:
        return message

    def deserialize(self, data: bytes) -> bytes:
        return data

    async def get_data(self) -> bytes:
        return await self.ipc_conn.call(b'get_data')

    async def send_data(self, data: bytes) -> None:
        await self.ipc_conn.call(b'send_data ' + data)


class MainInterface(IpcInterface[bytes]):
    __slots__ = ('manager',)

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager

    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        if cmd == b'get_data':
            return self.manager.get_data()
        elif cmd == b'send_data':
            self.manager.send_data(data)
            return b'success'
        raise AssertionError(request)

    def serialize(self, message: bytes) -> bytes:
        return message

    def deserialize(self, data: bytes) -> bytes:
        return data


class IpcLineReceiver(LineReceiver):
    __slots__ = ('_ipc_conn',)

    def __init__(self, ipc_conn: IpcConnection) -> None:
        self._ipc_conn = ipc_conn

    def lineReceived(self, data: bytes) -> None:
        deferred = self._ipc_conn.call(b'do_something ' + data)
        deferred.addCallback(lambda _: self.sendLine(b'echo ' + data))


class IpcFactory(ServerFactory):
    def __init__(self, reactor: ReactorProtocol, manager: HathorManager) -> None:
        self.reactor = reactor
        self.manager = manager

    def buildProtocol(self, addr: IAddress) -> IpcLineReceiver:
        main_rpc_conn = IpcConnection.fork(
            main_reactor=self.reactor,
            subprocess_name=str(addr.port),
            main_interface=MainInterface(self.manager),
            subprocess_interface=SubprocessInterface(),
        )
        return IpcLineReceiver(main_rpc_conn)


class HathorManager:
    def __init__(self, *, data: bytes):
        self._data = data

    def get_data(self) -> bytes:
        return self._data

    def send_data(self, data: bytes) -> None:
        print('printing received data from HathorManager: ', data, os.getpid())


def main():
    port = 8080
    reactor = initialize_global_reactor()
    manager = HathorManager(data=b'manager data')
    factory = IpcFactory(reactor, manager)
    reactor.listenTCP(port, factory)
    print(f'Server running on port {port}')
    reactor.run()


if __name__ == '__main__':
    main()
