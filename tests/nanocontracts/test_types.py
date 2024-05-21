from hathor.nanocontracts.serializers import Serializer
from hathor.nanocontracts.types import SignedData
from hathor.transaction.scripts import P2PKH
from tests import unittest


class BaseNanoContractTestCase(unittest.TestCase):
    def test_signed(self) -> None:
        from hathor.wallet import KeyPair

        serializer = Serializer()

        result = b'1x1'
        result_bytes = serializer.from_type(bytes, result)

        # Check signature using oracle's private key.
        key = KeyPair.create(b'123')
        assert key.address is not None
        script_input = key.p2pkh_create_input_data(b'123', result_bytes)
        signed_result: SignedData[bytes] = SignedData(result, script_input)

        p2pkh = P2PKH(key.address)
        oracle_script = p2pkh.get_script()
        self.assertTrue(signed_result.checksig(oracle_script))

        # Try to tamper with the data.
        fake_result = b'2x2'
        self.assertNotEqual(result, fake_result)
        invalid_signed_result = SignedData(fake_result, script_input)
        self.assertFalse(invalid_signed_result.checksig(oracle_script))

        # Try to use the wrong private key to sign the data.
        key2 = KeyPair.create(b'456')
        assert key2.address is not None
        p2pkh2 = P2PKH(key2.address)
        oracle_script2 = p2pkh2.get_script()
        self.assertFalse(signed_result.checksig(oracle_script2))

    def test_signed_eq(self):
        x = SignedData('data', b'signature')

        self.assertEqual(x, SignedData('data', b'signature'))
        self.assertNotEqual(x, SignedData('data', 'another-signature'))
        self.assertNotEqual(x, SignedData('another-data', 'signature'))
        self.assertNotEqual(x, SignedData('another-data', 'another-signature'))
