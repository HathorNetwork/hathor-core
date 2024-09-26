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

from hathor.multiprocess import ipc
from hathor.multiprocess.ipc import IpcInterface
from hathor.reactor import initialize_global_reactor, ReactorProtocol


class HathorProtocol:
    def __init__(self, interface: SubprocessInterface) -> None:
        self._interface = interface

    async def do_something(self, data: bytes) -> None:
        print('printing storage data from HathorProtocol: ', await self._interface.read_storage(), os.getpid())
        time.sleep(5)
        await self._interface.save_storage(data)
        await self._interface.send_line(b'some line ' + data)


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

    async def read_storage(self) -> bytes:
        return await self.ipc_conn.call(b'read_storage')

    async def save_storage(self, data: bytes) -> None:
        await self.ipc_conn.call(b'save_storage ' + data)

    async def send_line(self, data: bytes) -> None:
        await self.ipc_conn.call(b'send_line ' + data)


class MainInterface(IpcInterface[bytes]):
    __slots__ = ('manager', '_line_receiver')

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager
        self._line_receiver = None

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

    def serialize(self, message: bytes) -> bytes:
        return message

    def deserialize(self, data: bytes) -> bytes:
        return data

    def do_something(self, data: bytes) -> Deferred[bytes]:
        return self.ipc_conn.call(b'do_something ' + data)


class IpcLineReceiver(LineReceiver):
    __slots__ = ('_interface',)

    def __init__(self, interface: MainInterface) -> None:
        self._interface = interface

    def lineReceived(self, data: bytes) -> None:
        deferred = self._interface.do_something(data)
        deferred.addCallback(lambda _: self.sendLine(b'echo ' + data))


class IpcFactory(ServerFactory):
    def __init__(self, reactor: ReactorProtocol, manager: HathorManager) -> None:
        self.reactor = reactor
        self.manager = manager

    def buildProtocol(self, addr: IAddress) -> IpcLineReceiver:
        main_interface = MainInterface(self.manager)
        ipc.connect(
            main_reactor=self.reactor,
            subprocess_name=str(addr.port),
            main_interface=main_interface,
            subprocess_interface=SubprocessInterface(),
        )
        protocol = IpcLineReceiver(main_interface)
        main_interface._line_receiver = protocol
        return protocol


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
