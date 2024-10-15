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

from typing import Any, Callable, Coroutine, ParamSpec

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IDelayedCall

from hathor.reactor import ReactorProtocol

P = ParamSpec('P')


def call_coro_later(
    reactor: ReactorProtocol,
    delay: float,
    callable: Callable[P, Coroutine[Deferred[None], Any, None]],
    *args: P.args,
    **kwargs: P.kwargs,
) -> IDelayedCall:
    """Utility function for performing twisted's `reactor.callLater` on coroutines (async functions)."""
    coro = callable(*args, **kwargs)
    return reactor.callLater(delay, lambda: Deferred.fromCoroutine(coro))
