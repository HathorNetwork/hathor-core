# Copyright 2023 Hathor Labs
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

import os
from typing import List, Tuple

from hathor.p2p.manager import ConnectionsManager
from hathor.sysctl.exception import SysctlException
from hathor.sysctl.sysctl import Sysctl


def parse_text(text: str) -> List[str]:
    """Parse text per line skipping empty lines and comments."""
    ret: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            continue
        ret.append(line)
    return ret


class ConnectionsManagerSysctl(Sysctl):
    def __init__(self, connections: ConnectionsManager) -> None:
        super().__init__()

        self.connections = connections
        self.register(
            'max_enabled_sync',
            self.get_max_enabled_sync,
            self.set_max_enabled_sync,
        )
        self.register(
            'rate_limit.global.send_tips',
            self.get_global_send_tips_rate_limit,
            self.set_global_send_tips_rate_limit,
        )
        self.register(
            'sync_update_interval',
            self.get_lc_sync_update_interval,
            self.set_lc_sync_update_interval,
        )
        self.register(
            'force_sync_rotate',
            None,
            self.set_force_sync_rotate,
        )
        self.register(
            'always_enable_sync',
            self.get_always_enable_sync,
            self.set_always_enable_sync,
        )
        self.register(
            'always_enable_sync.readtxt',
            None,
            self.set_always_enable_sync_readtxt,
        )

    def set_force_sync_rotate(self) -> None:
        """Force a sync rotate."""
        self.connections._sync_rotate_if_needed(force=True)

    def get_global_send_tips_rate_limit(self) -> Tuple[int, float]:
        """Return the global rate limiter for SEND_TIPS."""
        limit = self.connections.rate_limiter.get_limit(self.connections.GlobalRateLimiter.SEND_TIPS)
        if limit is None:
            return (0, 0)
        return (limit.max_hits, limit.window_seconds)

    def set_global_send_tips_rate_limit(self, max_hits: int, window_seconds: float) -> None:
        """Change the global rate limiter for SEND_TIPS.

        The rate limiter is disabled when `window_seconds == 0`."""
        if window_seconds == 0:
            self.connections.disable_rate_limiter()
            return
        if max_hits < 0:
            raise SysctlException('max_hits must be >= 0')
        if window_seconds < 0:
            raise SysctlException('window_seconds must be >= 0')
        self.connections.enable_rate_limiter(max_hits, window_seconds)

    def get_lc_sync_update_interval(self) -> float:
        """Return the interval to rotate sync (in seconds)."""
        return self.connections.lc_sync_update_interval

    def set_lc_sync_update_interval(self, value: float) -> None:
        """Change the interval to rotate sync (in seconds)."""
        if value <= 0:
            raise SysctlException('value must be > 0')
        self.connections.lc_sync_update_interval = value
        if self.connections.lc_sync_update.running:
            self.connections.lc_sync_update.stop()
            self.connections.lc_sync_update.start(self.connections.lc_sync_update_interval, now=False)

    def get_always_enable_sync(self) -> List[str]:
        """Return the list of sync-always-enabled peers."""
        return list(self.connections.always_enable_sync)

    def set_always_enable_sync(self, values: List[str]) -> None:
        """Change the list of sync-always-enabled peers."""
        self.connections.set_always_enable_sync(values)

    def set_always_enable_sync_readtxt(self, file_path: str) -> None:
        """Update the list of sync-always-enabled peers from a file."""
        if not os.path.isfile(file_path):
            raise SysctlException(f'file not found: {file_path}')
        values: List[str]
        with open(file_path, 'r') as fp:
            values = parse_text(fp.read())
        self.connections.set_always_enable_sync(values)

    def get_max_enabled_sync(self) -> int:
        """Return the maximum number of peers running sync simultaneously."""
        return self.connections.MAX_ENABLED_SYNC

    def set_max_enabled_sync(self, value: int) -> None:
        """Change the maximum number of peers running sync simultaneously."""
        if value < 0:
            raise SysctlException('value must be >= 0')
        if value == self.connections.MAX_ENABLED_SYNC:
            return
        self.connections.MAX_ENABLED_SYNC = value
        self.connections._sync_rotate_if_needed(force=True)
