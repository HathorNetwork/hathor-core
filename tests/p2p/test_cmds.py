import os
import tempfile
from unittest.mock import MagicMock

from tests import unittest
from tests.simulation.base import SimulatorTestCase


class BaseRandomSimulatorTestCase(SimulatorTestCase):
    def test_cmd_p2p_max_enabled_sync(self):
        manager = self.create_peer()
        connections = manager.connections
        connections._sync_rotate_if_needed = MagicMock()
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 0)

        connections._execute_cmds([('p2p.max_enabled_sync', ['10'])])
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 1)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 10)

        connections._execute_cmds([('p2p.max_enabled_sync', ['10'])])
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 1)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 10)

        connections._execute_cmds([('p2p.max_enabled_sync', ['5'])])
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 2)
        self.assertEqual(connections.MAX_ENABLED_SYNC, 5)

    def test_cmd_global_rate_limiter_send_tips(self):
        manager = self.create_peer()
        connections = manager.connections

        connections._execute_cmds([('p2p.rate_limiter.global.send_tips', ['10', '4'])])
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, (10, 4))

        connections._execute_cmds([('p2p.rate_limiter.global.send_tips', ['15', '5'])])
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, (15, 5))

        connections._execute_cmds([('p2p.rate_limiter.global.send_tips', ['0', '0'])])
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, None)

        # Invalid value.
        connections._execute_cmds([('p2p.rate_limiter.global.send_tips', ['1.5', '2'])])
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, None)

        # Invalid value.
        connections._execute_cmds([('p2p.rate_limiter.global.send_tips', ['1', '2a'])])
        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, None)

    def test_files(self):
        manager = self.create_peer()
        connections = manager.connections
        connections._sync_rotate_if_needed = MagicMock()
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 0)

        with tempfile.TemporaryDirectory() as dir_path:
            content = [
                'p2p.rate_limiter.global.send_tips 50 4',
                'p2p.max_enabled_sync 0',
            ]
            fp = open(os.path.join(dir_path, 'p2p_params.txt'), 'w')
            fp.write('\n'.join(content))
            fp.close()

            content = [
                'peer-id-1',
                'peer-id-2',
            ]
            fp = open(os.path.join(dir_path, 'always_enable_sync.txt'), 'w')
            fp.write('\n'.join(content))
            fp.close()

            fp = open(os.path.join(dir_path, 'force_sync_rotate'), 'w')
            fp.close()

            manager.set_cmd_path(dir_path)
            connections.sync_update()

        limit = connections.rate_limiter.get_limit(connections.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(limit, (50, 4))
        self.assertEqual(connections.MAX_ENABLED_SYNC, 0)
        self.assertEqual(connections.always_enable_sync, {'peer-id-1', 'peer-id-2'})
        self.assertEqual(connections._sync_rotate_if_needed.call_count, 2)


class SyncV1RandomSimulatorTestCase(unittest.SyncV1Params, BaseRandomSimulatorTestCase):
    __test__ = True


class SyncV2RandomSimulatorTestCase(unittest.SyncV2Params, BaseRandomSimulatorTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeRandomSimulatorTestCase(unittest.SyncBridgeParams, SyncV2RandomSimulatorTestCase):
    __test__ = True
