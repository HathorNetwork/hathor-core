import os
import sys
import tempfile
from pathlib import Path

from twisted.internet.endpoints import UNIXServerEndpoint
from twisted.internet.interfaces import IReactorProcess
from twisted.internet.protocol import ProcessProtocol
from twisted.protocols import amp

from hathor.reactor import get_global_reactor, initialize_global_reactor, ReactorProtocol
from twisted.internet import protocol, reactor


class Sum(amp.Command):
    arguments = [(b"a", amp.Integer()), (b"b", amp.Integer())]
    response = [(b"total", amp.Integer())]


class Divide(amp.Command):
    arguments = [(b"numerator", amp.Integer()), (b"denominator", amp.Integer())]
    response = [(b"result", amp.Float())]
    errors = {ZeroDivisionError: b"ZERO_DIVISION"}


class Math(amp.AMP):
    @Sum.responder
    def sum(self, a, b):
        total = a + b
        print(f"Did a sum: {a} + {b} = {total}")
        return {"total": total}

    @Divide.responder
    def divide(self, numerator, denominator):
        result = float(numerator) / denominator
        print(f"Divided: {numerator} / {denominator} = {result}")
        return {"result": result}


def main():
    reactor: IReactorProcess = initialize_global_reactor()
    from twisted.internet.protocol import Factory

    pf = Factory()
    pf.protocol = Math

    tmp_dir = tempfile.TemporaryDirectory()
    socket = os.path.join(tmp_dir.name, 'my_sock.sock')
    endpoint = UNIXServerEndpoint(reactor=reactor, address=socket)
    endpoint.listen(pf)

    pp = protocol.ProcessProtocol()
    reactor.spawnProcess(
        processProtocol=pp,
        executable=sys.executable,
        args=[sys.executable, '/Users/glevco/Developer/hathor/hathor-core/hathor/ampclient.py', socket],
        env=os.environ,
        childFDs={1: 1, 2: 2},
    )

    print("started")
    reactor.run()
    tmp_dir.cleanup()


if __name__ == "__main__":
    main()
