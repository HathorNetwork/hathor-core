#  Copyright 2023 Hathor Labs
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

from typing import Any, Callable
from unittest.mock import Mock, patch

import pytest
from twisted.internet.testing import MemoryReactorClock

from hathor.pubsub import HathorEvents, PubSubManager


@pytest.mark.parametrize('is_in_main_thread', [False, True])
def test_memory_reactor_clock_not_running(is_in_main_thread: bool) -> None:
    """
    Running the PubSub with a non-running MemoryReactorClock makes it call the handler function directly,
    so it's executed before the plain function call. Threading makes no difference.
    """
    reactor = MemoryReactorClock()
    reactor.running = False
    pubsub = PubSubManager(reactor)
    handler = Mock()

    pubsub.subscribe(HathorEvents.MANAGER_ON_START, handler)

    with patch('hathor.pubsub.isInIOThread', lambda: is_in_main_thread):
        pubsub.publish(HathorEvents.MANAGER_ON_START)

    handler(HathorEvents.MANAGER_ON_STOP)

    assert len(handler.call_args_list) == 2
    assert handler.call_args_list[0].args[0] == HathorEvents.MANAGER_ON_START
    assert handler.call_args_list[1].args[0] == HathorEvents.MANAGER_ON_STOP


def test_memory_reactor_clock_running_no_threading() -> None:
    """
    When there's no threading, running the PubSub with a running MemoryReactorClock makes it call the handler function
    with callLater, so a plain function call gets executed before the handler.
    """
    reactor = MemoryReactorClock()
    reactor.running = True
    pubsub = PubSubManager(reactor)
    handler = Mock()

    pubsub.subscribe(HathorEvents.MANAGER_ON_START, handler)

    with patch('hathor.pubsub.isInIOThread', lambda: True):
        pubsub.publish(HathorEvents.MANAGER_ON_START)

    handler(HathorEvents.MANAGER_ON_STOP)

    reactor.advance(0)

    assert len(handler.call_args_list) == 2
    assert handler.call_args_list[0].args[0] == HathorEvents.MANAGER_ON_STOP
    assert handler.call_args_list[1].args[0] == HathorEvents.MANAGER_ON_START


def test_memory_reactor_clock_running_with_threading() -> None:
    """
    When there's threading, running the PubSub with a running MemoryReactorClock makes it call the handler function
    with callFromThread, so a plain function call gets executed before the handler.
    """
    reactor = MemoryReactorClock()
    reactor.running = True
    pubsub = PubSubManager(reactor)
    handler = Mock()

    def fake_call_from_thread(f: Callable[..., Any]) -> None:
        reactor.callLater(0, f)

    call_from_thread_mock = Mock(side_effect=fake_call_from_thread)
    setattr(reactor, 'callFromThread', call_from_thread_mock)

    pubsub.subscribe(HathorEvents.MANAGER_ON_START, handler)

    with (
        patch('hathor.pubsub.isInIOThread', lambda: False),
        patch('hathor.utils.zope.verifyObject', lambda _a, _b: True)
    ):
        pubsub.publish(HathorEvents.MANAGER_ON_START)

    handler(HathorEvents.MANAGER_ON_STOP)

    reactor.advance(10)

    assert len(handler.call_args_list) == 2
    assert handler.call_args_list[0].args[0] == HathorEvents.MANAGER_ON_STOP
    assert handler.call_args_list[1].args[0] == HathorEvents.MANAGER_ON_START
    assert call_from_thread_mock.call_count == 1
