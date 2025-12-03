import sys
from contextlib import redirect_stdout
from io import StringIO

from structlog.testing import capture_logs

from hathor_cli.multisig_address import create_parser, execute
from hathor_tests import unittest


class MultisigAddressTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = create_parser()

    def test_generate_address(self):
        # Generate address from 3 random pubkeys
        pubkey_count = 3
        args = self.parser.parse_args(['2', '--pubkey_count', '{}'.format(pubkey_count)])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args, '1234')
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        print('\n'.join(output), file=sys.stderr)
        self.assertEqual(len(output), pubkey_count * 11 + 6)

        def get_data(output, index):
            return output[index].split(':')[1].strip()

        pubkey1 = get_data(output, 6)
        pubkey2 = get_data(output, 16)
        pubkey3 = get_data(output, 26)
        redeem_script = get_data(output, 32)
        address = get_data(output, 37)

        # Generate address from given pubkeys
        args = self.parser.parse_args(['2', '--public_keys', '{},{},{}'.format(pubkey1, pubkey2, pubkey3)])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args, '1234')
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual(len(output), 9)

        redeem_script2 = get_data(output, 2)
        address2 = get_data(output, 7)

        # Validate the redeem script and address are the same in both generations
        self.assertEqual(redeem_script, redeem_script2)
        self.assertEqual(address, address2)

    def test_errors(self):
        args = self.parser.parse_args(['2'])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args, '1234')
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual(output[0], 'Error: you must give at least pubkey_count or public_keys')

        args = self.parser.parse_args(['2', '--pubkey_count', '17'])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args, '1234')
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual(output[0], 'Error: maximum number of public keys or signatures required is 16')
