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
        print('printing HathorManager data from HathorProtocol: ', self._manager.get_data())
        self._manager.send_data(data)


class MyLineReceiver(LineReceiver, HathorProtocol):
    def lineReceived(self, data: bytes) -> None:
        time.sleep(10)
        self.do_something(data)
        self.sendLine(b'echo ' + data)


class MyFactory(ServerFactory):
    def __init__(self, manager: HathorManager) -> None:
        self._manager = manager

    def buildProtocol(self, addr: IAddress) -> "Optional[Protocol]":
        return MyLineReceiver(self._manager)


class HathorManager:
    def __init__(self, *, data: bytes):
        self._data = data

    def get_data(self) -> bytes:
        return self._data

    def send_data(self, data: bytes) -> None:
        print('printing received data from HathorManager: ', data)


if __name__ == '__main__':
    port = 8080
    reactor = initialize_global_reactor()
    manager = HathorManager(data=b'manager data')
    factory = MyFactory(manager)
    reactor.listenTCP(port, factory)
    print(f'Server running on port {port}')
    reactor.run()
