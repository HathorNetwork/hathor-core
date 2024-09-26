from __future__ import annotations

import os
import time

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

from hathor.multiprocess.process_rpc import ProcessRPC, ProcessRPCHandler
from hathor.reactor import initialize_global_reactor


class HathorProtocol:
    def __init__(self, rpc: ProcessRPC) -> None:
        self._rpc = rpc

    async def do_something(self, data: bytes) -> None:
        print('printing HathorManager data from HathorProtocol: ', await self._rpc.call(b'get_data'), os.getpid())
        await self._rpc.call(b'send_data ' + data)


class MainHandler(ProcessRPCHandler[bytes]):
    def __init__(self, manager: HathorManager) -> None:
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


class SubprocessHandler(ProcessRPCHandler[bytes]):
    def __init__(self) -> None:
        self.protocol: HathorProtocol | None = None

    async def handle_request(self, request: bytes) -> bytes:
        cmd, _, data = request.partition(b' ')
        assert cmd == b'do_something', request
        await self.protocol.do_something(data)
        return b'success'

    def serialize(self, message: bytes) -> bytes:
        return message

    def deserialize(self, data: bytes) -> bytes:
        return data


class ProcessLineReceiver(LineReceiver):
    def __init__(self, rpc: ProcessRPC) -> None:
        self._rpc = rpc

    def lineReceived(self, data: bytes) -> None:
        time.sleep(5)
        deferred = self._rpc.call(b'do_something ' + data)
        deferred.addCallback(lambda _: self.sendLine(b'echo ' + data))


class MyFactory(ServerFactory):
    def __init__(self, rpc: ProcessRPC) -> None:
        self._rpc = rpc

    def buildProtocol(self, addr: IAddress) -> "Optional[Protocol]":
        return ProcessLineReceiver(self._rpc)


class HathorManager:
    def __init__(self, *, data: bytes):
        self._data = data

    def get_data(self) -> bytes:
        return self._data

    def send_data(self, data: bytes) -> None:
        print('printing received data from HathorManager: ', data, os.getpid())


async def sub_callback(rpc: ProcessRPC) -> None:
    rpc._handler.protocol = HathorProtocol(rpc)


if __name__ == '__main__':
    port = 8080
    reactor = initialize_global_reactor()
    manager = HathorManager(data=b'manager data')
    main_rpc = ProcessRPC.fork(
        main_reactor=reactor,
        target=sub_callback,
        subprocess_name='sub',
        main_handler=MainHandler(manager),
        subprocess_handler=SubprocessHandler(),
    )
    factory = MyFactory(main_rpc)
    reactor.listenTCP(port, factory)
    print(f'Server running on port {port}')
    reactor.run()
