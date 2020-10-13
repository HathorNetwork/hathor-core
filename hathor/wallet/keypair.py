import base64
from typing import Any, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_address_b58_from_public_key, get_private_key_bytes, get_private_key_from_bytes
from hathor.wallet.exceptions import IncorrectPassword, WalletLocked


class KeyPair:
    private_key_bytes: Optional[bytes]
    address: Optional[str]
    used: bool

    def __init__(self, private_key_bytes: Optional[bytes] = None, address: Optional[str] = None,
                 used: bool = False) -> None:
        """Holds the address in base58 and the encrypted bytes of the private key

        :param address: string in base58
        """
        self.private_key_bytes = private_key_bytes
        self.address = address
        self.used = used
        self._cache_priv_key_unlock: Optional[ec.EllipticCurvePrivateKeyWithSerialization] = None

    def __eq__(self, other: object) -> bool:
        """Override the default Equals behavior"""
        if not isinstance(other, KeyPair):
            return NotImplemented
        return self.address == other.address

    def get_private_key_b64(self) -> str:
        """
        :return: Private key in base64.
        :rtype: string(base64)
        """
        assert self.private_key_bytes is not None
        return base64.b64encode(self.private_key_bytes).decode('utf-8')

    def clear_cache(self) -> None:
        """ Clear cache of the unencrypted private key
        """
        self._cache_priv_key_unlock = None

    def get_private_key(self, password: bytes) -> ec.EllipticCurvePrivateKeyWithSerialization:
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
        priv_key: ec.EllipticCurvePrivateKeyWithSerialization
        if self._cache_priv_key_unlock is not None:
            priv_key = self._cache_priv_key_unlock
        else:
            try:
                assert self.private_key_bytes is not None
                priv_key = self._cache_priv_key_unlock = get_private_key_from_bytes(self.private_key_bytes,
                                                                                    password=password)
            except ValueError:
                raise IncorrectPassword
        return priv_key

    def to_json(self) -> Dict[str, Any]:
        return {
            'privKey': self.get_private_key_b64(),
            'address': self.address,
            'used': self.used,
        }

    @classmethod
    def from_json(cls, json_data: Dict[str, Any]) -> 'KeyPair':
        priv_key_bytes = base64.b64decode(json_data['privKey'])
        address = json_data['address']
        used = json_data['used']
        return cls(private_key_bytes=priv_key_bytes, address=address, used=used)

    @classmethod
    def create(cls, password: Optional[bytes]) -> 'KeyPair':
        """
        :raises WalletLocked: wallet password was not provided
        """
        if not password:
            raise WalletLocked

        new_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        assert isinstance(new_key, ec.EllipticCurvePrivateKeyWithSerialization)
        private_key_bytes = get_private_key_bytes(new_key,
                                                  encryption_algorithm=serialization.BestAvailableEncryption(password))
        address = get_address_b58_from_public_key(new_key.public_key())
        return cls(private_key_bytes=private_key_bytes, address=address, used=False)
