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
import functools
import time

from twisted.internet.defer import inlineCallbacks, Deferred
from twisted.internet.task import deferLater
from twisted.python.failure import Failure

from hathor.manager import HathorManager
from hathor.reactor import get_global_reactor
from hathor.simulator import Simulator
from hathor.simulator.clock import MemoryReactorHeapClock
from hathor.simulator.utils import add_new_block
from tests import unittest


def timer(func):

    """Print the runtime of the decorated function"""

    @functools.wraps(func)

    def wrapper_timer(*args, **kwargs):

        start_time = time.perf_counter()

        value = func(*args, **kwargs)

        end_time = time.perf_counter()

        run_time = end_time - start_time

        print(f"Finished {func.__name__}() in {run_time:.4f} secs")

        return value

    return wrapper_timer

class TestAsync(unittest.TestCase):

    def run(self):
        pass

    def __init__(self, methodName: str) -> None:

        assert hasattr(self, methodName)

        original_method = getattr(self, methodName)
        decorated_method = timer(original_method)
        setattr(self, methodName, decorated_method)
        super().__init__(methodName)

    # @inlineCallbacks
    # def test_global_reactor(self) -> None:
    #     reactor = get_global_reactor()
    #     d = Deferred()
    #
    #     start = reactor.seconds()
    #     reactor.callLater(3, lambda: d.callback(123))
    #     result = yield d
    #     end = reactor.seconds()
    #
    #     assert result == 123
    #     assert end - start >= 3

    # @inlineCallbacks
    # def test_memory_clock0(self) -> None:
    #     clock = MemoryReactorHeapClock()
    #     d = Deferred()
    #
    #     clock.callLater(3, lambda: d.callback(123))
    #     result = yield d
    #
    #     assert result == 123

    def test_memory_clock1(self) -> None:
        clock = MemoryReactorHeapClock()

        @inlineCallbacks
        def f() -> None:
            d = Deferred()

            clock.callLater(3, lambda: d.callback(123))
            result = yield d
            print(result)

            raise Exception('AJSDAJSD')
            assert False
            assert result == 123

        d = f()

        for call in clock.getDelayedCalls():
            amount = call.getTime() - clock.seconds()
            clock.advance(amount)

        assert d.called

        if isinstance(d.result, Failure):
            d.result.raiseException()

    def test_memory_clock2(self) -> None:
        clock = MemoryReactorHeapClock()

        async def f() -> None:
            d = Deferred()

            clock.callLater(3, lambda: d.callback(123))
            result = await d
            print(result)

            # raise Exception('AJSDAJSD')
            # assert False
            # assert result == 123

        d = Deferred.fromCoroutine(f())

        for call in clock.getDelayedCalls():
            amount = call.getTime() - clock.seconds()
            clock.advance(amount)

        assert d.called

        if isinstance(d.result, Failure):
            d.result.raiseException()

    def test_memory_clock3(self) -> None:
        clock: MemoryReactorHeapClock

        async def f() -> None:
            nonlocal clock
            simulator = Simulator()
            simulator.start()
            clock = simulator._clock
            manager = simulator.create_peer()

            block1 = await add_new_block(manager)
            block2 = await add_new_block(manager)

            print(block2)

            simulator.stop()
            # assert block2 == 999

        d = Deferred.fromCoroutine(f())

        for call in clock.getDelayedCalls():
            amount = call.getTime() - clock.seconds()
            if amount > 0:
                clock.advance(amount)

        assert d.called

        if isinstance(d.result, Failure):
            d.result.raiseException()

    async def test_f(self, clock: MemoryReactorHeapClock) -> None:
        simulator = Simulator(clock=clock)
        simulator.start()
        manager = simulator.create_peer()

        block1 = await add_new_block(manager)
        block2 = await add_new_block(manager)

        print(block2)

        simulator.stop()
        # assert block2 == 999
