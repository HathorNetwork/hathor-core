import shutil
import tempfile

from hathor.util import json_loadb
from hathor_cli.wallet import create_parser, execute
from hathor_tests import unittest


class WalletTest(unittest.TestCase):
    def test_wallet(self):
        parser = create_parser()

        tmpdir = tempfile.mkdtemp()

        count = 5
        args = parser.parse_args(['--count', '{}'.format(count), '--directory', tmpdir])
        execute(args, '1234')

        with open('{}/keys.json'.format(tmpdir), 'rb') as f:
            data = json_loadb(f.read())

        self.assertEqual(len(data), 5)

        # Removing tmpdir
        shutil.rmtree(tmpdir)
