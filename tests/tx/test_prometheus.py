import os
import shutil
import tempfile

from hathor.prometheus import PrometheusMetricsExporter
from tests import unittest
from tests.utils import add_new_blocks, add_new_transactions


class PrometheusTest(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

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
