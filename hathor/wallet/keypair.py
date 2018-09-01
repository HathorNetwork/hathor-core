from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import base64
import base58
import hashlib


class KeyPair(object):
    def __init__(self, private_key=None, used=False):
        self.private_key = private_key
        if self.private_key is None:
            self._generate_key()
        self.public_key = self.private_key.public_key()
        self.used = used

    def _generate_key(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

    def get_private_key(self, encoding=serialization.Encoding.DER):
        return self.private_key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_private_key_b64(self):
        return base64.b64encode(self.get_private_key).decode('utf-8')

    def get_public_key(self, encoding=serialization.Encoding.DER):
        return self.public_key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key_b64(self):
        return base64.b64encode(self.get_private_key).decode('utf-8')

    def get_address(self):
        # TODO secp256k1 public keys generated with cryptography are
        # not 32/33 bytes long as expected. We'd have to manually convert
        # the public numbers to get it
        h1 = hashlib.sha256(self.get_public_key())
        h2 = hashlib.new('ripemd160')
        h2.update(h1.digest())
        return h2.digest()

    def get_address_b58(self):
        return base58.b58encode(self.get_address())

    def to_json(self):
        return {
            'privKey': self.get_private_key_b64(),
            'address': self.get_address_b58(),
            'used': self.used,
        }
