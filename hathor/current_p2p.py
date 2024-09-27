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

import time

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

from hathor.reactor import initialize_global_reactor


class HathorProtocol:
    def __init__(self, manager: HathorManager) -> None:
        self._manager = manager

    def do_something(self, data: bytes) -> None:
        print('printing HathorManager data from HathorProtocol: ', self._manager.read_storage())
        time.sleep(5)
        self._manager.save_storage(data)
        self.send_line(b'some line ' + data)

    def send_line(self, data: bytes) -> None:
        raise NotImplementedError


class MyLineReceiver(LineReceiver, HathorProtocol):
    def lineReceived(self, data: bytes) -> None:
        self.do_something(data)

    def send_line(self, data: bytes) -> None:
        self.sendLine(data)


class MyFactory(ServerFactory):
    def __init__(self, manager: HathorManager) -> None:
        self._manager = manager

    def buildProtocol(self, addr: IAddress) -> MyLineReceiver:
        return MyLineReceiver(self._manager)


class HathorManager:
    def __init__(self, *, storage: bytes):
        self._storage = storage

    def read_storage(self) -> bytes:
        return self._storage

    def save_storage(self, data: bytes) -> None:
        print('printing from HathorManager.save_storage: ', data)


def main() -> None:
    port = 8080
    reactor = initialize_global_reactor()
    manager = HathorManager(storage=b'manager storage')
    factory = MyFactory(manager)
    reactor.listenTCP(port, factory)
    print(f'Server running on port {port}')
    reactor.run()


if __name__ == '__main__':
    main()
