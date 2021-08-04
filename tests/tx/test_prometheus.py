import os
import shutil
import sys
import tempfile

import pytest

from hathor.prometheus import PrometheusMetricsExporter
from tests import unittest
from tests.utils import add_new_blocks, add_new_transactions


class BasePrometheusTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

    @pytest.mark.skipif(sys.platform == 'win32', reason='set_new_metrics fails on Windows')
    def test_wallet(self):
        tmpdir = tempfile.mkdtemp()
        tmpfile = tempfile.NamedTemporaryFile(dir=tmpdir, suffix='.prom', delete=False)
        filename = os.path.basename(tmpfile.name)
        full_path = os.path.join(tmpdir, filename)

        prometheus = PrometheusMetricsExporter(metrics=self.manager.metrics, path=tmpdir, filename=filename)
        prometheus.set_new_metrics()

        with open(full_path, 'r') as f:
            text = f.read().split('\n')
            self.assertEqual(text[5], 'blocks 1.0')
            self.assertEqual(text[2], 'transactions 2.0')

        add_new_blocks(self.manager, 30, advance_clock=1)
        add_new_transactions(self.manager, 5, advance_clock=1)

        with open(full_path, 'r') as f:
            text = f.read().split('\n')
            self.assertEqual(text[5], 'blocks 1.0')
            self.assertEqual(text[2], 'transactions 2.0')

        self.run_to_completion()
        prometheus.set_new_metrics()
        with open(full_path, 'r') as f:
            text = f.read().split('\n')
            self.assertEqual(text[5], 'blocks 31.0')
            self.assertEqual(text[2], 'transactions 7.0')

        # Removing tmpdir
        shutil.rmtree(tmpdir)


class SyncV1PrometheusTest(unittest.SyncV1Params, BasePrometheusTest):
    __test__ = True


class SyncV2PrometheusTest(unittest.SyncV2Params, BasePrometheusTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgePrometheusTest(unittest.SyncBridgeParams, SyncV2PrometheusTest):
    pass
