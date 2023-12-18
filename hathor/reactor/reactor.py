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

from typing import cast

from twisted.internet.interfaces import IReactorCore, IReactorTCP, IReactorTime
from zope.interface.verify import verifyObject

from hathor.reactor.reactor_protocol import ReactorProtocol

# Internal variable that should NOT be accessed directly.
_reactor: ReactorProtocol | None = None


def get_global_reactor() -> ReactorProtocol:
    """
    Get the global Twisted reactor. It should be the only way to get a reactor, other than using the instance that
    is passed around (which should be the same instance as the one returned by this function).
    """
    global _reactor

    if _reactor is not None:
        return _reactor

    from twisted.internet import reactor as twisted_reactor

    assert verifyObject(IReactorTime, twisted_reactor) is True
    assert verifyObject(IReactorCore, twisted_reactor) is True
    assert verifyObject(IReactorTCP, twisted_reactor) is True

    # We cast to ReactorProtocol, our own type that stubs the necessary Twisted zope interfaces, to aid typing.
    _reactor = cast(ReactorProtocol, twisted_reactor)
    return _reactor
