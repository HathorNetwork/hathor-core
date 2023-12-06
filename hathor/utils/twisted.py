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

from typing import Callable, ParamSpec, TypeVar, cast

from twisted.internet import defer
from twisted.internet.base import ReactorBase
from twisted.internet.defer import Deferred

from hathor.reactor.reactor_protocol import ReactorProtocol

T = TypeVar('T')
P = ParamSpec('P')


def call_blocking(reactor: ReactorProtocol, f: Callable[P, T], *a: P.args, **kw: P.kwargs) -> T:
    """
    https://github.com/twisted/twisted/blob/twisted-22.10.0/src/twisted/internet/base.py#L1320
    """
    assert isinstance(reactor, ReactorBase), f'Reactor of type "{type(reactor)}" must inherit from ReactorBase.'
    d: Deferred[T] = defer.maybeDeferred(f, *a, **kw)

    while not d.called:
        reactor.runUntilCurrent()
        t2 = reactor.timeout()
        t = reactor.running and t2
        reactor.doIteration(t)

    return cast(T, d.result)
