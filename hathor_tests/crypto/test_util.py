import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import (
    decode_address,
    get_address_b58_from_public_key,
    get_address_from_public_key,
    get_private_key_bytes,
    get_private_key_from_bytes,
)


class CryptoUtilTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        assert isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization)
        self.private_key = key
        self.public_key = self.private_key.public_key()

    def test_privkey_serialization(self) -> None:
        private_key_bytes = get_private_key_bytes(self.private_key)
        self.assertEqual(self.private_key.private_numbers(),
                         get_private_key_from_bytes(private_key_bytes).private_numbers())

    def test_address(self) -> None:
        address = get_address_from_public_key(self.public_key)
        address_b58 = get_address_b58_from_public_key(self.public_key)
        self.assertEqual(address, decode_address(address_b58))

    def test_invalid_address(self) -> None:
        from hathor.wallet.exceptions import InvalidAddress
        address_b58 = get_address_b58_from_public_key(self.public_key)
        address_b58 += '0'      # 0 is invalid in base58
        with self.assertRaises(InvalidAddress):
            decode_address(address_b58)
