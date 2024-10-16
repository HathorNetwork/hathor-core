import sys

from twisted.internet.defer import Deferred

from ampserver import Divide, Sum

from twisted.internet import defer, reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol, UNIXClientEndpoint
from twisted.protocols.amp import AMP


async def doMath(socket):
    destination = UNIXClientEndpoint(reactor=reactor, path=socket)
    ampProto = await connectProtocol(destination, AMP())
    result = await ampProto.callRemote(Sum, a=13, b=81)
    result_sum = result["total"]

    try:
        result_div = await ampProto.callRemote(Divide, numerator=1234, denominator=0)
    except ZeroDivisionError:
        print("Divided by zero: returning INF")
        result_div = 1e1000

    print("Done with math:", result_sum, result_div)
    reactor.stop()

if __name__ == "__main__":
    socket = sys.argv[1]
    Deferred.fromCoroutine(doMath(socket))
    reactor.run()

