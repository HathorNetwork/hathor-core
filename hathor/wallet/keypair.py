from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hathor.crypto.util import get_private_key_bytes, get_private_key_from_bytes, \
                               get_address_b58_from_public_key
from hathor.wallet.exceptions import WalletLocked, IncorrectPassword

import base64


class KeyPair(object):
    def __init__(self, private_key_bytes=None, address=None, used=False):
        """Holds the address in base58 and the encrypted bytes of the private key

        :type private_key_bytes: bytes

        :type address: string(base58)

        :type used: bool
        """
        self.private_key_bytes = private_key_bytes
        self.address = address
        self.used = used

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.address == other.address

    def get_private_key_b64(self):
        """
        :return: Private key in base64.
        :rtype: string(base64)
        """
        return base64.b64encode(self.private_key_bytes).decode('utf-8')

    def get_private_key(self, password):
        """
        :param password: password to decode private key
        :type password: bytes

        :return: Private key object.
        :rtype: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

        :raises WalletLocked: wallet password was not provided
        :raises IncorrectPassword: password provided cannot decrypt keys
        """
        if not password:
            raise WalletLocked
        try:
            return get_private_key_from_bytes(self.private_key_bytes, password=password)
        except ValueError:
            raise IncorrectPassword

    def to_json(self):
        return {
            'privKey': self.get_private_key_b64(),
            'address': self.address,
            'used': self.used,
        }

    @classmethod
    def from_json(cls, json_data):
        priv_key_bytes = base64.b64decode(json_data['privKey'])
        address = json_data['address']
        used = json_data['used']
        return cls(private_key_bytes=priv_key_bytes, address=address, used=used)

    @classmethod
    def create(cls, password):
        """
        :raises WalletLocked: wallet password was not provided
        """
        if not password:
            raise WalletLocked

        new_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        private_key_bytes = get_private_key_bytes(
            new_key,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        address = get_address_b58_from_public_key(new_key.public_key())
        return cls(private_key_bytes=private_key_bytes, address=address, used=False)
