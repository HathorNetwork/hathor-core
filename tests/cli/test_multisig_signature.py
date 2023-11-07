import hashlib
import shutil
import tempfile
from contextlib import redirect_stdout
from io import StringIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from structlog.testing import capture_logs

from hathor.cli.multisig_signature import create_parser, execute
from hathor.simulator.utils import add_new_blocks
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_transactions


class BaseSignatureTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

        self.tmpdir = tempfile.mkdtemp()
        self.wallet = Wallet(directory=self.tmpdir)
        self.wallet.unlock(b'123')

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.tmpdir)

    def test_generate_signature(self):
        add_new_blocks(self.manager, 1, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        tx = add_new_transactions(self.manager, 1, advance_clock=1)[0]

        address = self.wallet.get_unused_address()
        keypair = self.wallet.keys[address]
        private_key_hex = keypair.private_key_bytes.hex()

        private_key = keypair.get_private_key(b'123')
        public_key = private_key.public_key()

        parser = create_parser()

        # Generate signature to validate
        args = parser.parse_args([tx.get_struct().hex(), private_key_hex])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args, '123')
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        signature = bytes.fromhex(output[0].split(':')[1].strip())

        # Now we validate that the signature is correct
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        self.assertIsNone(public_key.verify(signature, hashed_data, ec.ECDSA(hashes.SHA256())))


class SyncV1SignatureTest(unittest.SyncV1Params, BaseSignatureTest):
    __test__ = True


class SyncV2SignatureTest(unittest.SyncV2Params, BaseSignatureTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSignatureTest(unittest.SyncBridgeParams, SyncV2SignatureTest):
    pass
