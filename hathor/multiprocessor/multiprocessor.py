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

from multiprocessing import Pool
from typing import Callable, ParamSpec, TypeVar

from structlog import get_logger
from twisted.internet.defer import Deferred

logger = get_logger()

T = TypeVar('T')
P = ParamSpec('P')


class Multiprocessor:
    __slots__ = ('_log', '_pool',)

    def __init__(self, processes: int | None = None) -> None:
        self._log = logger.new()
        self._pool = Pool(processes=processes, initializer=_init_worker)

    def stop(self) -> None:
        self._log.info('Stopping Multiprocessor pool')
        self._pool.terminate()
        self._pool.join()
        self._log.info('Stopped Multiprocessor pool')

    def run(self, fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> Deferred[T]:
        """Run a function in a separate process and receive its result asynchronously, as a Deferred."""
        # from twisted.internet.task import deferLater
        # from hathor.reactor import get_global_reactor
        # return deferLater(get_global_reactor(), 0, fn, *args, **kwargs)
        deferred = Deferred[T]()
        self._pool.apply_async(fn, args, kwargs, callback=deferred.callback, error_callback=deferred.errback)
        return deferred


def _init_worker() -> None:
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)
