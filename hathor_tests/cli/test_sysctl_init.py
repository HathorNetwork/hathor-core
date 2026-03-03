import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from hathor.builder.sysctl_builder import SysctlBuilder
from hathor.sysctl.exception import SysctlEntryNotFound, SysctlRunnerException
from hathor.sysctl.init_file_loader import SysctlInitFileLoader
from hathor.sysctl.runner import SysctlRunner
from hathor_cli.run_node import RunNode
from hathor_tests import unittest


class SysctlInitTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        super().tearDown()
        # Removing tmpdir
        shutil.rmtree(self.tmp_dir)

    def test_sysctl_builder_fail_with_invalid_property(self):
        file_content = [
            'invalid.property=10',
        ]

        with tempfile.NamedTemporaryFile(
                dir=self.tmp_dir,
                suffix='.txt',
                prefix='sysctl_',
                delete=False) as sysctl_init_file:
            sysctl_init_file.write('\n'.join(file_content).encode())
            sysctl_init_file_path = str(Path(sysctl_init_file.name))

        # prepare to register only p2p commands
        artifacts = Mock(**{
            'p2p_manager': Mock(),
            'manager.websocket_factory': None,
            'settings.ENABLE_NANO_CONTRACTS': False,
        })

        with self.assertRaises(SysctlEntryNotFound) as context:
            root = SysctlBuilder(artifacts).build()
            runner = SysctlRunner(root)
            loader = SysctlInitFileLoader(runner, sysctl_init_file_path)
            loader.load()

        # assert message in the caught exception
        expected_msg = 'invalid.property'
        self.assertEqual(str(context.exception), expected_msg)

    def test_sysctl_builder_fail_with_invalid_value(self):
        file_content = [
            'p2p.rate_limit.global.send_tips=!!tuple [1,2]'
        ]

        with tempfile.NamedTemporaryFile(
                dir=self.tmp_dir,
                suffix='.txt',
                prefix='sysctl_',
                delete=False) as sysctl_init_file:
            sysctl_init_file.write('\n'.join(file_content).encode())
            sysctl_init_file_path = str(Path(sysctl_init_file.name))

        # prepare to register only p2p commands
        artifacts = Mock(**{
            'p2p_manager': Mock(),
            'manager.websocket_factory': None,
            'settings.ENABLE_NANO_CONTRACTS': False,
        })

        with self.assertRaises(SysctlRunnerException) as context:
            root = SysctlBuilder(artifacts).build()
            runner = SysctlRunner(root)
            loader = SysctlInitFileLoader(runner, sysctl_init_file_path)
            loader.load()

        # assert message in the caught exception
        expected_msg = 'value: wrong format'
        self.assertEqual(str(context.exception), expected_msg)

    def test_syctl_init_file_fail_with_empty_or_invalid_file(self):
        # prepare to register only p2p commands
        artifacts = Mock(**{
            'p2p_manager': Mock(),
            'manager.websocket_factory': None,
            'settings.ENABLE_NANO_CONTRACTS': False,
        })

        with self.assertRaises(AssertionError):
            root = SysctlBuilder(artifacts).build()
            runner = SysctlRunner(root)
            loader = SysctlInitFileLoader(runner, None)
            loader.load()

        with self.assertRaises(AssertionError):
            root = SysctlBuilder(artifacts).build()
            runner = SysctlRunner(root)
            loader = SysctlInitFileLoader(runner, "")
            loader.load()

    @patch('twisted.internet.endpoints.serverFromString')  # avoid open sock
    def test_command_option_sysctl_init_file(self, mock_endpoint):
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        expected_sysctl_dict = {
            'p2p.max_enabled_sync': 7,
            'p2p.rate_limit.global.send_tips': (5, 3),
            'p2p.sync_update_interval': 17,
        }

        file_content = [
            'p2p.max_enabled_sync=7',
            'p2p.rate_limit.global.send_tips=5,3',
            'p2p.sync_update_interval=17',
        ]

        with tempfile.NamedTemporaryFile(
                dir=self.tmp_dir,
                suffix='.txt',
                prefix='sysctl_',
                delete=False) as sysctl_init_file:
            sysctl_init_file.write('\n'.join(file_content).encode())
            sysctl_init_file_path = str(Path(sysctl_init_file.name))

        run_node = CustomRunNode(argv=[
            '--sysctl', 'tcp:8181',
            '--sysctl-init-file', sysctl_init_file_path,  # relative to src/hathor
            '--temp-data',
        ])
        self.assertTrue(run_node is not None)
        conn = run_node.manager.connections

        curr_max_enabled_sync = conn.MAX_ENABLED_SYNC
        self.assertEqual(
                curr_max_enabled_sync,
                expected_sysctl_dict['p2p.max_enabled_sync'])

        curr_rate_limit_global_send_tips = conn.rate_limiter.get_limit(conn.GlobalRateLimiter.SEND_TIPS)
        self.assertEqual(
                curr_rate_limit_global_send_tips.max_hits,
                expected_sysctl_dict['p2p.rate_limit.global.send_tips'][0])
        self.assertEqual(
                curr_rate_limit_global_send_tips.window_seconds,
                expected_sysctl_dict['p2p.rate_limit.global.send_tips'][1])

        curr_sync_update_interval = conn.lc_sync_update_interval
        self.assertEqual(
                curr_sync_update_interval,
                expected_sysctl_dict['p2p.sync_update_interval'])

        # assert always_enabled_sync when it is set with a file
        peer_1 = '0e2bd0d8cd1fb6d040801c32ec27e8986ce85eb8810b6c878dcad15bce3b5b1e'
        peer_2 = '2ff0d2c80c50f724de79f132a2f8cae576c64b57ea531d400577adf7db3e7c15'
        expected_sysctl_dict = {
            'p2p.always_enable_sync': [peer_1, peer_2],
        }

        file_content = [
            peer_1,
            peer_2,
        ]

        # set the always_enabled_sync peers file
        with tempfile.NamedTemporaryFile(
                dir=self.tmp_dir,
                suffix='.txt',
                prefix='always_enable_sync_',
                delete=False) as always_enabled_peers_file:
            always_enabled_peers_file.write('\n'.join(file_content).encode())
            always_enabled_peers_file_path = str(Path(always_enabled_peers_file.name))

        file_content = [
            f'p2p.always_enable_sync.readtxt={json.dumps(always_enabled_peers_file_path)}'
        ]

        # set the sysctl.txt file
        with tempfile.NamedTemporaryFile(
                dir=self.tmp_dir,
                suffix='.txt',
                prefix='sysctl_',
                delete=False) as sysctl_init_file:
            sysctl_init_file.write('\n'.join(file_content).encode())
            sysctl_init_file_path = str(Path(sysctl_init_file.name))

        run_node = CustomRunNode(argv=[
            '--sysctl', 'tcp:8181',
            '--sysctl-init-file', sysctl_init_file_path,  # relative to src/hathor
            '--temp-data',
        ])
        self.assertTrue(run_node is not None)
        conn = run_node.manager.connections

        curr_always_enabled_sync = list(map(str, conn.always_enable_sync))
        self.assertTrue(
                set(curr_always_enabled_sync).issuperset(set(expected_sysctl_dict['p2p.always_enable_sync'])))
