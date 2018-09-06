from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hathor.crypto.util import get_private_key_bytes, get_public_key_bytes, \
                               get_address_from_public_key, get_address_b58_from_public_key

import base64


class KeyPair(object):
    def __init__(self, private_key=None, used=False):
        self.private_key = private_key
        if self.private_key is None:
            self._generate_key()
        self.public_key = self.private_key.public_key()
        self.used = used

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.get_address_b58() == other.get_address_b58()

    def _generate_key(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

    def get_private_key(self, encoding=serialization.Encoding.DER):
        return get_private_key_bytes(self.private_key)

    def get_private_key_b64(self):
        return base64.b64encode(self.get_private_key()).decode('utf-8')

    def get_public_key(self, encoding=serialization.Encoding.DER):
        return get_public_key_bytes(self.public_key)

    def get_public_key_b64(self):
        return base64.b64encode(self.get_public_key()).decode('utf-8')

    def get_address(self):
        # TODO secp256k1 public keys generated with cryptography are
        # not 32/33 bytes long as expected. We'd have to manually convert
        # the public numbers to get it
        return get_address_from_public_key(self.public_key)

    def get_address_b58(self):
        return get_address_b58_from_public_key(self.public_key)

    def to_json(self):
        return {
            'privKey': self.get_private_key_b64(),
            'address': self.get_address_b58(),
            'used': self.used,
        }

    @classmethod
    def from_json(cls, json_data):
        from hathor.crypto.util import get_private_key_from_bytes
        priv_key_data = base64.b64decode(json_data['privKey'])
        private_key = get_private_key_from_bytes(priv_key_data)
        used = json_data['used']
        return cls(private_key=private_key, used=used)
