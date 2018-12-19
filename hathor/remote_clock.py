from hathor import protos
from hathor.grpc_util import StubConnect, convert_grpc_exceptions, convert_hathor_exceptions


class RemoteClockFactory:
    def __init__(self, clock_port):
        self._clock_port = clock_port

    def __call__(self):
        remote_clock = RemoteClock()
        remote_clock.connect_to(self._clock_port)
        return remote_clock


class RemoteClock(StubConnect):
    @classmethod
    def get_stub_class(cls):
        return protos.ClockStub

    @convert_grpc_exceptions
    def advance(self, amount):
        self._check_connection()
        request = protos.AdvanceRequest(amount=amount)
        self._stub.Advance(request)


class RemoteClockServicer(protos.ClockServicer):
    def __init__(self, clock):
        self.clock = clock

    @convert_hathor_exceptions
    def Advance(self, request, context):
        self.clock.advance(request.amount)
        return protos.AdvanceResponse()
