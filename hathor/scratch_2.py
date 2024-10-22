import os
import select
import sys
from socket import AF_UNIX
import socket

from structlog import get_logger
from twisted.internet.protocol import Protocol, Factory

from hathor.reactor import initialize_global_reactor
from hathor.wallet.resources.thin_wallet.address_history import logger

log = get_logger()

# import pydevd_pycharm
# pydevd_pycharm.settrace('localhost', port=8090, stdoutToServer=True, stderrToServer=True)

_, fileno = sys.argv
fileno = int(fileno)
print('--sub pid', os.getpid(), fileno)
sys.stdout.flush()


# WORKING
# s = socket.fromfd(fileno, AF_UNIX, socket.SOCK_STREAM)
# s.setblocking(False)
# # print('will read')
# sys.stdout.flush()
# # print('NEW', s.recv(100))
# sys.stdout.flush()
#
# # List of sockets to monitor for incoming data
# sockets_to_monitor = [s]
# print('--running')
# sys.stdout.flush()
#
# count = 0
# while True:
#     if count > 2:
#         break
#     readable, writable, exceptional = select.select(sockets_to_monitor, [], [])
#     assert len(readable) == 1
#     sock = readable[0]
#     assert sock is s
#     data = sock.recv(100)
#     assert data
#     print('--NEW', data)
#     sys.stdout.flush()






reactor = initialize_global_reactor()

class MyProtocol(Protocol):
    def dataReceived(self, data: bytes) -> None:
        log.new().info('--NEW', a=os.getpid(), b=data)

    def connectionLost(self, reason):
        log.new().info('--bye bye', c=reason.getErrorMessage())


reactor.callWhenRunning(reactor.adoptStreamConnection, fileno, AF_UNIX, Factory.forProtocol(MyProtocol))


reactor.run()
