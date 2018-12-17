from hathor.cli.peer_id import main

from tests import unittest
import ast

from io import StringIO
from contextlib import redirect_stdout


class PeerIdTest(unittest.TestCase):
    def test_peer_id(self):
        f = StringIO()
        with redirect_stdout(f):
            main()
        # Transforming prints str in array
        output = f.getvalue().split('\n')
        # Last element is always empty string
        output.pop()

        peer_id = ast.literal_eval("".join(output))
        self.assertTrue('id' in peer_id)
        self.assertTrue('pubKey' in peer_id)
        self.assertTrue('entrypoints' in peer_id)
        self.assertTrue('privKey' in peer_id)
