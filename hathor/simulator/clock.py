# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import heapq
from typing import Any, Callable, List

from twisted.internet.base import DelayedCall
from twisted.internet.interfaces import IDelayedCall, IReactorTime
from twisted.internet.testing import MemoryReactor
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

    def seconds(self) -> float:
        """
        Pretend to be time.time().  This is used internally when an operation
        such as L{IDelayedCall.reset} needs to determine a time value
        relative to the current time.
        @rtype: C{float}
        @return: The time which should be considered the current time.
        """
        return self.rightNow

    def callLater(self, delay: float, callable: Callable[..., Any], *args: object, **kwargs: object) -> IDelayedCall:
        """
        See L{twisted.internet.interfaces.IReactorTime.callLater}.
        """
        dc = DelayedCall(self.seconds() + delay,
                         callable, args, kwargs,
                         lambda c: None,
                         lambda c: None,
                         self.seconds)
        heapq.heappush(self.calls, (dc.getTime(), dc))
        return dc

    def getDelayedCalls(self) -> List[IDelayedCall]:
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


class MemoryReactorHeapClock(MemoryReactor, HeapClock):
    def __init__(self):
        MemoryReactor.__init__(self)
        HeapClock.__init__(self)
