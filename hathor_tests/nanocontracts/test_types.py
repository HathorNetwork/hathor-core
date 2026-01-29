from hathor.nanocontracts.types import ContractId, SignedData, VertexId
from hathor_tests import unittest
from hathorlib.scripts import P2PKH


class BaseNanoContractTestCase(unittest.TestCase):
    def test_signed(self) -> None:
        from hathor.wallet import KeyPair

        nc_id = ContractId(VertexId(b'x' * 32))

        result = b'1x1'
        signed_result = SignedData[bytes](result, b'')
        result_bytes = signed_result.get_data_bytes(nc_id)

        # Check signature using oracle's private key.
        key = KeyPair.create(b'123')
        assert key.address is not None
        script_input = key.p2pkh_create_input_data(b'123', result_bytes)
        signed_result = SignedData[bytes](result, script_input)

        p2pkh = P2PKH(key.address)
        oracle_script = p2pkh.get_script()
        self.assertTrue(signed_result.checksig(nc_id, oracle_script))

        # Try to tamper with the data.
        fake_result = b'2x2'
        self.assertNotEqual(result, fake_result)
        invalid_signed_result = SignedData[bytes](fake_result, script_input)
        self.assertFalse(invalid_signed_result.checksig(nc_id, oracle_script))

        # Try to use the wrong private key to sign the data.
        key2 = KeyPair.create(b'456')
        assert key2.address is not None
        p2pkh2 = P2PKH(key2.address)
        oracle_script2 = p2pkh2.get_script()
        self.assertFalse(signed_result.checksig(nc_id, oracle_script2))

    def test_signed_eq(self):
        x = SignedData[str]('data', b'signature')

        self.assertEqual(x, SignedData[str]('data', b'signature'))
        self.assertNotEqual(x, SignedData[str]('data', b'another-signature'))
        self.assertNotEqual(x, SignedData[str]('another-data', 'signature'))
        self.assertNotEqual(x, SignedData[str]('another-data', 'another-signature'))
