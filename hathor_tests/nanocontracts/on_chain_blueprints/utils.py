from cryptography.hazmat.primitives.asymmetric import ec

from hathor.wallet import KeyPair
from hathor_tests import unittest


def get_ocb_private_key() -> ec.EllipticCurvePrivateKey:
    """Return the private key used to sign on-chain blueprints on tests."""
    key = KeyPair(unittest.OCB_TEST_PRIVKEY)
    return key.get_private_key(unittest.OCB_TEST_PASSWORD)
