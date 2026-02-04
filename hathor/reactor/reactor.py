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

from structlog import get_logger
from twisted.internet.interfaces import IReactorCore, IReactorTCP, IReactorTime
from zope.interface.verify import verifyObject

from hathor.reactor.reactor_protocol import ReactorProtocol

logger = get_logger()

# Internal variable that should NOT be accessed directly.
_reactor: ReactorProtocol | None = None


def get_global_reactor() -> ReactorProtocol:
    """
    Get the global Twisted reactor. It should be the only way to get a reactor, other than using the instance that
    is passed around (which should be the same instance as the one returned by this function).

    This function must NOT be called in the module-level, only inside other functions.
    """
    global _reactor

    if _reactor is None:
        raise Exception('The reactor is not initialized. Use `initialize_global_reactor()`.')

    return _reactor


def initialize_global_reactor(*, use_asyncio_reactor: bool = False) -> ReactorProtocol:
    """
    Initialize the global Twisted reactor. Must ony be called once.
    This function must NOT be called in the module-level, only inside other functions.
    """
    global _reactor

    if _reactor is not None:
        log = logger.new()
        log.warn('The reactor has already been initialized. Use `get_global_reactor()`.')
        return _reactor

    if use_asyncio_reactor:
        import asyncio

        from twisted.internet import asyncioreactor
        from twisted.internet.error import ReactorAlreadyInstalledError

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            asyncioreactor.install(loop)
        except ReactorAlreadyInstalledError as e:
            msg = (
                "There's a Twisted reactor installed already. It's probably the default one, installed indirectly by "
                "one of our imports. This can happen, for example, if we import from the hathor module in "
                "entrypoint-level, like in CLI tools other than `RunNode`. Debug it by setting a breakpoint in "
                "`installReactor()` in the `twisted/internet/main.py` file."

            )
            raise Exception(msg) from e

    from twisted.internet import reactor as twisted_reactor

    assert verifyObject(IReactorTime, twisted_reactor) is True
    assert verifyObject(IReactorCore, twisted_reactor) is True
    assert verifyObject(IReactorTCP, twisted_reactor) is True

    # We cast to ReactorProtocol, our own type that stubs the necessary Twisted zope interfaces, to aid typing.
    _reactor = cast(ReactorProtocol, twisted_reactor)
    return _reactor
