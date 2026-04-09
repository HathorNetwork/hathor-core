from contextlib import redirect_stdout
from io import StringIO

from structlog.testing import capture_logs

from hathor.util import json_loadb
from hathor_cli.peer_id import main
from hathor_tests import unittest


class PeerIdTest(unittest.TestCase):
    def test_peer_id(self):
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                main()
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        peer_id = json_loadb(''.join(output))
        self.assertTrue('id' in peer_id)
        self.assertTrue('pubKey' in peer_id)
        self.assertTrue('entrypoints' in peer_id)
        self.assertTrue('privKey' in peer_id)
