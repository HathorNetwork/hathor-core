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

import sys
from contextlib import contextmanager
from typing import Callable, Iterator, NoReturn

import structlog
from structlog import get_logger

from hathor.reactor import ReactorProtocol

logger = get_logger()


class ExecutionManager:
    """Class to manage actions related to full node execution."""
    __slots__ = ('_log', '_reactor', '_on_crash_callbacks')

    def __init__(self, reactor: ReactorProtocol) -> None:
        self._log = logger.new()
        self._reactor = reactor
        self._on_crash_callbacks: list[tuple[int, Callable[[], None]]] = []

    def register_on_crash_callback(self, callback: Callable[[], None], *, priority: int = 0) -> None:
        """Register a callback to be executed before the full node exits."""
        self._on_crash_callbacks.append((priority, callback))

    def _run_on_crash_callbacks(self) -> None:
        """Run all registered on crash callbacks."""
        callbacks = sorted(self._on_crash_callbacks, reverse=True, key=lambda item: item[0])

        for _, callback in callbacks:
            try:
                callback()
            except BaseException as e:
                self._log.critical(f'Failed execution of on_crash callback "{callback}". Exception: {repr(e)}')

    def crash_and_exit(self, *, reason: str) -> NoReturn:
        """
        Calling this function is a very extreme thing to do, so be careful. It should only be called when a
        critical, unrecoverable failure happens. It crashes and exits the full node, maybe rendering the database
        corrupted, and requiring manual intervention. In other words, a restart with a clean database (from scratch
        or a snapshot) may be required.
        """
        self._run_on_crash_callbacks()
        self._log.critical(
            'Critical failure occurred, causing the full node to halt execution. Manual intervention is required.',
            reason=reason,
            exc_info=True
        )
        # We sequentially call more extreme exit methods, so the full node exits as gracefully as possible, while
        # guaranteeing that it will indeed exit.
        self._reactor.stop()
        self._reactor.crash()
        sys.exit(-1)


@contextmanager
def non_critical_code(log: structlog.stdlib.BoundLogger) -> Iterator[None]:
    """Use this context manager to ignore all exceptions in the contained code."""
    try:
        yield
    except BaseException:
        log.exception('ignoring error in non-critical code')
