import os
import sys
import time

import psutil
from twisted.internet import unix
from twisted.internet.endpoints import UNIXClientEndpoint, UNIXServerEndpoint
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import Protocol, Factory, ProcessProtocol

from hathor.reactor import initialize_global_reactor

# class MyProcessProtocol(ProcessProtocol):
#     def __init__(self, og_transport):
#         self.og_transport = og_transport
#
#     def outReceived(self, data: bytes) -> None:
#         print('recv', data)
#         self.og_transport.loseConnection()



class MyProtocol(Protocol):
    def dataReceived(self, data: bytes) -> None:
        print('OLD', os.getpid(), data)

    def makeConnection(self, transport: ITransport) -> None:
        assert isinstance(transport, unix.Server)
        fileno = transport.fileno()
        print('file', fileno)
        transport.reactor.spawnProcess(
            processProtocol=ProcessProtocol(),
            executable=sys.executable,
            args=[
                sys.executable,
                '/Users/glevco/Library/Application Support/JetBrains/PyCharm2024.2/scratches/scratch_2.py',
                str(fileno)
            ],
            childFDs={1: 1, 2: 2, fileno: fileno},
        )
        # time.sleep(4)
        # transport.loseConnection()
        transport.socket.close()

def main() -> None:
    socket_file = '/tmp/uds'
    if os.path.exists(socket_file):
        os.remove(socket_file)

    print('main pid', os.getpid())
    reactor = initialize_global_reactor()

    endpoint = UNIXServerEndpoint(reactor, socket_file)
    endpoint.listen(Factory.forProtocol(MyProtocol))

    reactor.run()

if __name__ == '__main__':
    main()
