# Copyright 2024 Hathor Labs
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

from hathor.manager import HathorManager
from hathor.sysctl.sysctl import Sysctl


class HathorManagerSysctl(Sysctl):
    def __init__(self, manager: HathorManager) -> None:
        super().__init__()

        self.manager = manager
        self.register(
            'profiler.status',
            self.get_profiler_status,
            None
        )
        self.register(
            'profiler.start',
            None,
            self.set_profiler_start,
        )
        self.register(
            'profiler.stop',
            None,
            self.set_profiler_stop,
        )

    def get_profiler_status(self) -> tuple[int, float]:
        """Return (enabled, duration) as a profiler status.

        enabled: 0 means disabled / 1 means enabled.
        duration: time in seconds since the profiler has been started.
        """
        if not self.manager.is_profiler_running:
            return (0, 0)
        now = self.manager.reactor.seconds()
        duration = now - self.manager.profiler_last_start_time
        return (1, duration)

    def set_profiler_start(self, reset: bool) -> None:
        """Start the profiler. One can safely call start multiple times to reset it."""
        self.manager.start_profiler(reset=reset)

    def set_profiler_stop(self, save_to: str | None) -> None:
        """Stop the profiler and optionally dump the statistics to a file.

        An empty save_to will skip the dump.
        """
        if not save_to:
            save_to = None
        self.manager.stop_profiler(save_to=save_to)
