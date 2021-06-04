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

import asyncio
from asyncio import Future
from contextlib import suppress
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple, Union

from structlog import get_logger
from twisted.internet.defer import Deferred, ensureDeferred

logger = get_logger()


class Periodic:
    """ Create an asyncio task that calls an async function periodically.

    Adapted from:
    - https://stackoverflow.com/a/37514633/947511
    - https://stackoverflow.com/a/55505152/947511
    """

    def __init__(self,
                 afunc: Callable[..., Awaitable[None]],
                 interval: Union[int, float],
                 args: Tuple = (),
                 kwargs: Dict = {}):
        """ Create Periodic instance from async function, `interval` is in seconds.
        """
        self.afunc = afunc
        self.args = args
        self.kwargs = kwargs
        self.interval = interval
        self.is_started = False
        self._task: Optional[Future[None]] = None

    async def start(self) -> None:
        if not self.is_started:
            self.is_started = True
            # Start task to call func periodically:
            self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        if self.is_started:
            assert self._task is not None
            self.is_started = False
            # Stop task and await it stopped:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        assert self._task is not None
        while self.is_started:
            try:
                await asyncio.gather(
                    self.afunc(*self.args, **self.kwargs),
                    asyncio.sleep(self.interval),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception('periodic call failed')
                break


def as_future(d: Deferred) -> Callable[..., Awaitable[Any]]:
    """Convert twisted deferred to asyncio future."""
    return d.asFuture(asyncio.get_event_loop())


def as_deferred(f: Awaitable[Any]) -> Deferred:
    """Convert asyncio future to twisted deferred."""
    return Deferred.fromFuture(asyncio.ensure_future(f))


def ensure_deferred(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        result = f(*args, **kwargs)
        return ensureDeferred(result)
    return wrapper
