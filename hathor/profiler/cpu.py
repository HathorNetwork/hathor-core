# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from collections import defaultdict
from functools import wraps
from typing import Any, Callable, Union

from twisted.internet.task import LoopingCall

Key = tuple[str, ...]


class ProcItem:
    """Store information for each process."""
    def __init__(self) -> None:
        self.last_total_time: float = 0.
        self.total_time: float = 0.
        self.percent_cpu: float = 0.
        self.last_seen: float = -1

    def add_time(self, dt: float) -> None:
        """Add `dt` to the total time."""
        self.total_time += dt
        self.last_seen = time.time()

    def update(self, interval: float) -> None:
        """Update CPU percent. Should be called periodically."""
        dt = self.total_time - self.last_total_time
        self.percent_cpu = dt / interval * 100
        self.last_total_time = self.total_time


class SimpleCPUProfiler:
    """Simple CPU Profiler where each "process" is a list of keys."""

    def __init__(self, *, update_interval: float = 3.0, expiry: float = 15.0):
        """Initialize the profiler.

        It calculates the statistics every `update_interval` seconds, and removes
        a process of the list if it is idle for more then `expiry` seconds.

        TODO Add max_depth for protection.
        """

        # Store the measures for each key.
        self.measures: defaultdict[Key, ProcItem] = defaultdict(ProcItem)

        # Error message if something goes wrong.
        self.error: str = ''

        # Stack of the current sequence of markers.
        self.stack: list[tuple[str, float]] = []

        # Wall time when update was last called.
        self.last_update = time.time()

        # Process time when update was last called.
        self.last_process_time = 0.0

        # List of processes and their data. It is the output of the profiler.
        self.proc_list: list[tuple[Key, ProcItem]] = []

        # Timer to call `self.update()` periodically.
        self.lc_update: LoopingCall | None = None

        # Interval to update the list of processes.
        self.update_interval = update_interval

        # Maximum idle time before a process expires.
        self.expiry = expiry

        # True if the profiler is enabled.
        self.enabled = False

        # Let's reset to start!
        self.reset()

    def reset(self) -> None:
        """Reset all data."""
        self.measures = defaultdict(ProcItem)
        self.error = ''
        self.stack = []
        self.last_update = time.time()
        self.last_process_time = time.process_time()
        self.proc_list = []

    def start(self) -> None:
        """Start the profiler."""
        if self.enabled:
            return
        self.reset()
        self.enabled = True
        self.lc_update = LoopingCall(self.update)
        self.lc_update.start(self.update_interval)

    def stop(self) -> None:
        """Stop the profiler."""
        if not self.enabled:
            return
        self.enabled = False
        assert self.lc_update is not None
        self.lc_update.stop()

    def get_proc_list(self) -> list[tuple[Key, ProcItem]]:
        """Return the process list."""
        return self.proc_list

    def mark_begin(self, key: str) -> None:
        """Begin a new mark to collect time.

        Every call to this method must generate a call to `mark_end(...)`.
        """
        if not self.enabled:
            return
        self.stack.append((key, time.process_time()))

    def mark_end(self, key: str) -> bool:
        """End a mark and add the time to the process."""
        if not self.enabled:
            return False

        t0 = time.process_time()

        if not self.stack:
            self.error = 'mark_end without mark_begin (key={})'.format(key)
            return False

        cur_key, cur_time = self.stack[-1]
        if cur_key != key:
            self.error = 'mark_end mismatch key (cur={}, key={})'.format(cur_key, key)
            return False

        dt = time.process_time() - cur_time
        self.measures[tuple(x[0] for x in self.stack)].add_time(dt)
        self.stack.pop()

        t1 = time.process_time()
        self.measures[('profiler',)].add_time(t1 - t0)
        return True

    def update(self) -> None:
        """Update the process list."""
        if not self.enabled:
            return

        t0 = time.process_time()

        ptime = time.process_time()
        interval = ptime - self.last_process_time

        proc_list: list[tuple[Key, ProcItem]] = []

        # Update keys.
        keys_to_remove = set()
        for key, proc in self.measures.items():
            if time.time() - proc.last_seen > self.expiry:
                keys_to_remove.add(key)
            else:
                proc.update(interval)
                proc_list.append((key, proc))

        # Remove expired keys.
        for key in keys_to_remove:
            self.measures.pop(key)

        proc_list.sort(key=lambda x: x[1].percent_cpu, reverse=True)

        self.proc_list = proc_list
        self.last_process_time = ptime
        self.last_update = time.time()

        t1 = time.process_time()
        self.measures[('profiler',)].add_time(t1 - t0)

    def profiler(self, key: Union[str, Callable[..., str]]) -> Callable[[Callable[..., Any]], Any]:
        """Decorator to collect data. The `key` must be the key itself
        or a method that returns the key.

        When `key` is a method and has parameters, it gets exactly the same
        parameters as the decorated method.
        """
        def _decorator(fn):
            from inspect import getfullargspec
            if callable(key):
                argspec = getfullargspec(key)
                nargs = len(argspec.args)

            @wraps(fn)
            def _wrapper(*args, **kwargs):
                if callable(key):
                    real_key = key(*args[:nargs])
                else:
                    real_key = key

                self.mark_begin(real_key)
                try:
                    ret = fn(*args, **kwargs)
                finally:
                    self.mark_end(real_key)
                return ret
            return _wrapper
        return _decorator
