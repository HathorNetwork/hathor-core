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

from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.peer_id import PeerId
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import discover_hostname
from hathor.sysctl.exception import SysctlException
from hathor.sysctl.sysctl import Sysctl, signal_handler_safe

AUTO_HOSTNAME_TIMEOUT_SECONDS: float = 5


def parse_text(text: str) -> list[str]:
    """Parse text per line skipping empty lines and comments."""
    ret: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            continue
        ret.append(line)
    return ret


def parse_sync_version(name: str) -> SyncVersion:
    match name.strip():
        case 'v1':
            return SyncVersion.V1_1
        case 'v2':
            return SyncVersion.V2
        case _:
            raise ValueError('unknown or not implemented')


def pretty_sync_version(sync_version: SyncVersion) -> str:
    match sync_version:
        case SyncVersion.V1_1:
            return 'v1'
        case SyncVersion.V2:
            return 'v2'
        case _:
            raise ValueError('unknown or not implemented')


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
        self.register(
            'available_sync_versions',
            self.get_available_sync_verions,
            None,
        )
        self.register(
            'enabled_sync_versions',
            self.get_enabled_sync_versions,
            self.set_enabled_sync_versions,
        )
        self.register(
            'kill_connection',
            None,
            self.set_kill_connection,
        )
        self.register(
            'hostname',
            self.get_hostname,
            self.set_hostname,
        )
        self.register(
            'refresh_auto_hostname',
            None,
            self.refresh_auto_hostname,
        )
        self.register(
            'reload_entrypoints_and_connections',
            None,
            self.reload_entrypoints_and_connections,
        )

    def set_force_sync_rotate(self) -> None:
        """Force a sync rotate."""
        self.connections._sync_rotate_if_needed(force=True)

    def get_global_send_tips_rate_limit(self) -> tuple[int, float]:
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

    def get_always_enable_sync(self) -> list[str]:
        """Return the list of sync-always-enabled peers."""
        return list(map(str, self.connections.always_enable_sync))

    def set_always_enable_sync(self, values: list[str]) -> None:
        """Change the list of sync-always-enabled peers."""
        self.connections.set_always_enable_sync(list(map(PeerId, values)))

    def set_always_enable_sync_readtxt(self, file_path: str) -> None:
        """Update the list of sync-always-enabled peers from a file."""
        if not os.path.isfile(file_path):
            raise SysctlException(f'file not found: {file_path}')
        values: list[str]
        with open(file_path, 'r') as fp:
            values = parse_text(fp.read())
        self.connections.set_always_enable_sync(list(map(PeerId, values)))

    def get_max_enabled_sync(self) -> int:
        """Return the maximum number of peers running sync simultaneously."""
        return self.connections.MAX_ENABLED_SYNC

    @signal_handler_safe
    def set_max_enabled_sync(self, value: int) -> None:
        """Change the maximum number of peers running sync simultaneously."""
        if value < 0:
            raise SysctlException('value must be >= 0')
        if value == self.connections.MAX_ENABLED_SYNC:
            return
        self.connections.MAX_ENABLED_SYNC = value
        self.connections._sync_rotate_if_needed(force=True)

    def get_available_sync_verions(self) -> list[str]:
        """Return the list of AVAILABLE sync versions."""
        return sorted(map(pretty_sync_version, self.connections.get_available_sync_versions()))

    def get_enabled_sync_versions(self) -> list[str]:
        """Return the list of ENABLED sync versions."""
        return sorted(map(pretty_sync_version, self.connections.get_enabled_sync_versions()))

    @signal_handler_safe
    def set_enabled_sync_versions(self, sync_versions: list[str]) -> None:
        """Set the list of ENABLED sync versions."""
        new_sync_versions = set(map(parse_sync_version, sync_versions))
        old_sync_versions = self.connections.get_enabled_sync_versions()
        to_enable = new_sync_versions - old_sync_versions
        to_disable = old_sync_versions - new_sync_versions
        for sync_version in to_enable:
            self._enable_sync_version(sync_version)
        for sync_version in to_disable:
            self._disable_sync_version(sync_version)

    def _enable_sync_version(self, sync_version: SyncVersion) -> None:
        """Enable the given sync version, it must be available, otherwise it will fail silently."""
        if not self.connections.is_sync_version_available(sync_version):
            self.connections.log.warn('tried to enable a sync version through sysctl, but it is not available',
                                      sync_version=sync_version)
            return
        self.connections.enable_sync_version(sync_version)

    def _disable_sync_version(self, sync_version: SyncVersion) -> None:
        """Disable the given sync version."""
        self.connections.disable_sync_version(sync_version)

    @signal_handler_safe
    def set_kill_connection(self, peer_id: str, force: bool = False) -> None:
        """Kill connection with peer_id or kill all connections if peer_id == '*'."""
        if peer_id == '*':
            self.log.warn('Killing all connections')
            self.connections.disconnect_all_peers(force=force)
            return

        try:
            peer_id_obj = PeerId(peer_id)
        except ValueError:
            raise SysctlException('invalid peer-id')
        conn = self.connections.get_ready_peer_by_id(peer_id_obj)
        if conn is None:
            self.log.warn('Killing connection', peer_id=peer_id)
            raise SysctlException('peer-id is not connected')
        conn.disconnect(force=force)

    def get_hostname(self) -> str | None:
        """Return the configured hostname."""
        assert self.connections.manager is not None
        return self.connections.manager.hostname

    def set_hostname(self, hostname: str) -> None:
        """Set the hostname and reset all connections."""
        assert self.connections.manager is not None
        self.connections.manager.set_hostname_and_reset_connections(hostname)

    def refresh_auto_hostname(self) -> None:
        """
        Automatically discover the hostname and set it, if it's found. This operation blocks the event loop.
        Then, reset all connections.
        """
        assert self.connections.manager is not None
        try:
            hostname = discover_hostname(timeout=AUTO_HOSTNAME_TIMEOUT_SECONDS)
        except Exception as e:
            self.log.error(f'Could not refresh hostname. Error: {str(e)}')
            return

        if hostname:
            self.connections.manager.set_hostname_and_reset_connections(hostname)

    def reload_entrypoints_and_connections(self) -> None:
        """Kill all connections and reload entrypoints from the peer config file."""
        self.connections.reload_entrypoints_and_connections()
