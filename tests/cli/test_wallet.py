from tests import unittest
from hathor.cli.wallet import create_parser, execute
import tempfile
import json


class WalletTest(unittest.TestCase):
    def test_wallet(self):
        parser = create_parser()

        tmpdir = tempfile.mkdtemp()

        count = 5
        args = parser.parse_args(['--count', '{}'.format(count), '--directory', tmpdir])
        execute(args, '1234')

        with open('{}/keys.json'.format(tmpdir), 'rb') as f:
            data = json.loads(f.read())

        self.assertEqual(len(data), 5)
