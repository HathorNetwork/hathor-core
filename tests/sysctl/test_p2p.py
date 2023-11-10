import os
import tempfile
from unittest.mock import MagicMock

from hathor.sysctl import ConnectionsManagerSysctl
from hathor.sysctl.exception import SysctlException
from tests import unittest
from tests.simulation.base import SimulatorTestCase


class BaseRandomSimulatorTestCase(SimulatorTestCase):
    def test_max_enabled_sync(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        connections._sync_rotate_if_needed = MagicMock()
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 0)

        sysctl.set('max_enabled_sync', 10)
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 1)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 10)
        self.assertEqual(sysctl.get('max_enabled_sync'), 10)

        sysctl.set('max_enabled_sync', 10)
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 1)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 10)
        self.assertEqual(sysctl.get('max_enabled_sync'), 10)

        sysctl.set('max_enabled_sync', 5)
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 2)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 5)
        self.assertEqual(sysctl.get('max_enabled_sync'), 5)

        sysctl.set('max_enabled_sync', 0)
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 3)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 0)
        self.assertEqual(sysctl.get('max_enabled_sync'), 0)

        with self.assertRaises(SysctlException):
            sysctl.set('max_enabled_sync', -1)

    def test_global_rate_limiter_send_tips(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        path = 'rate_limit.global.send_tips'

        sysctl.set(path, (10, 4))
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, (10, 4))
        self.assertEqual(sysctl.get(path), (10, 4))

        sysctl.set(path, (15, 5))
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, (15, 5))
        self.assertEqual(sysctl.get(path), (15, 5))

        sysctl.set(path, (0, 0))
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, None)
        self.assertEqual(sysctl.get(path), (0, 0))

        with self.assertRaises(SysctlException):
            sysctl.set(path, (-1, 1))

        with self.assertRaises(SysctlException):
            sysctl.set(path, (1, -1))

        with self.assertRaises(SysctlException):
            sysctl.set(path, (-1, -1))

    def test_force_sync_rotate(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        connections._sync_rotate_if_needed = MagicMock()
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 0)

        sysctl.set('force_sync_rotate', ())
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 1)
        self.assertEqual(connections._sync_rotate_if_needed.call_args.kwargs, {'force': True})

    def test_sync_update_interval(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        sysctl.set('sync_update_interval', 10)
        self.assertEqual(connections.lc_sync_update_interval, 10)
        self.assertEqual(sysctl.get('sync_update_interval'), 10)

        with self.assertRaises(SysctlException):
            sysctl.set('sync_update_interval', -1)

    def test_always_enable_sync(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        sysctl.set('always_enable_sync', ['peer-1', 'peer-2'])
        self.assertEqual(connections.always_enable_sync, {'peer-1', 'peer-2'})
        self.assertEqual(set(sysctl.get('always_enable_sync')), {'peer-1', 'peer-2'})

        sysctl.set('always_enable_sync', [])
        self.assertEqual(connections.always_enable_sync, set())
        self.assertEqual(sysctl.get('always_enable_sync'), [])

        with tempfile.TemporaryDirectory() as dir_path:
            content = [
                'peer-id-1',
                'peer-id-2',
            ]

            file_path = os.path.join(dir_path, 'a.txt')
            fp = open(file_path, 'w')
            fp.write('\n'.join(content))
            fp.close()

            sysctl.set('always_enable_sync.readtxt', file_path)
            self.assertEqual(connections.always_enable_sync, set(content))
            self.assertEqual(set(sysctl.get('always_enable_sync')), set(content))

    def test_available_sync_versions(self):
        from hathor.p2p.sync_version import SyncVersion

        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        self.assertEqual(sysctl.get('available_sync_versions'), ['v1', 'v2'])

        del connections._sync_factories[SyncVersion.V2]
        self.assertEqual(sysctl.get('available_sync_versions'), ['v1'])

    def _default_enabled_sync_versions(self) -> list[str]:
        raise NotImplementedError

    def test_enabled_sync_versions(self):
        manager = self.create_peer()
        connections = manager.connections
        sysctl = ConnectionsManagerSysctl(connections)

        self.assertEqual(sysctl.get('enabled_sync_versions'), self._default_enabled_sync_versions())
        sysctl.set('enabled_sync_versions', ['v1', 'v2'])
        self.assertEqual(sysctl.get('enabled_sync_versions'), ['v1', 'v2'])
        sysctl.set('enabled_sync_versions', ['v2'])
        self.assertEqual(sysctl.get('enabled_sync_versions'), ['v2'])
        sysctl.set('enabled_sync_versions', ['v1'])
        self.assertEqual(sysctl.get('enabled_sync_versions'), ['v1'])


class SyncV1RandomSimulatorTestCase(unittest.SyncV1Params, BaseRandomSimulatorTestCase):
    __test__ = True

    def _default_enabled_sync_versions(self) -> list[str]:
        return ['v1']


class SyncV2RandomSimulatorTestCase(unittest.SyncV2Params, BaseRandomSimulatorTestCase):
    __test__ = True

    def _default_enabled_sync_versions(self) -> list[str]:
        return ['v2']


# sync-bridge should behave like sync-v2
class SyncBridgeRandomSimulatorTestCase(unittest.SyncBridgeParams, SyncV2RandomSimulatorTestCase):
    __test__ = True

    def _default_enabled_sync_versions(self) -> list[str]:
        return ['v1', 'v2']
