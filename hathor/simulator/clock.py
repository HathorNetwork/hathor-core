import heapq

from twisted.internet import base
from twisted.internet.interfaces import IReactorTime
from zope.interface import implementer


@implementer(IReactorTime)
class HeapClock:
    """
    Provide a deterministic, easily-controlled implementation of
    L{IReactorTime.callLater}.  This is commonly useful for writing
    deterministic unit tests for code which schedules events using this API.
    """

    rightNow = 0.0

    def __init__(self):
        self.calls = []

    def seconds(self):
        """
        Pretend to be time.time().  This is used internally when an operation
        such as L{IDelayedCall.reset} needs to determine a time value
        relative to the current time.
        @rtype: C{float}
        @return: The time which should be considered the current time.
        """
        return self.rightNow

    def callLater(self, when, what, *a, **kw):
        """
        See L{twisted.internet.interfaces.IReactorTime.callLater}.
        """
        dc = base.DelayedCall(self.seconds() + when,
                              what, a, kw,
                              lambda c: None,
                              lambda c: None,
                              self.seconds)
        heapq.heappush(self.calls, (dc.getTime(), dc))
        return dc

    def getDelayedCalls(self):
        """
        See L{twisted.internet.interfaces.IReactorTime.getDelayedCalls}
        """
        return [dc for _, dc in self.calls]

    def advance(self, amount):
        """
        Move time on this clock forward by the given amount and run whatever
        pending calls should be run.
        @type amount: C{float}
        @param amount: The number of seconds which to advance this clock's
        time.
        """
        assert amount >= 0
        self.rightNow += amount
        while self.calls:
            time, call = self.calls[0]  # smallest item
            if time > self.seconds():
                break
            heapq.heappop(self.calls)
            if not call.cancelled:
                call.called = 1
                call.func(*call.args, **call.kw)

    def pump(self, timings):
        """
        Advance incrementally by the given set of times.
        @type timings: iterable of C{float}
        """
        for amount in timings:
            self.advance(amount)
