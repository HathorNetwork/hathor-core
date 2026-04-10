# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)

from hathor.util import not_none
from hathorlib.utils.address import (  # noqa: F401
    decode_address,
    get_address_b58_from_bytes,
    get_address_b58_from_public_key,
    get_address_b58_from_public_key_bytes,
    get_address_b58_from_public_key_hash,
    get_address_b58_from_redeem_script_hash,
    get_address_from_public_key_hash,
    get_address_from_redeem_script_hash,
    get_checksum,
    get_hash160,
    get_public_key_bytes_compressed,
    get_public_key_from_bytes_compressed,
    is_pubkey_compressed,
)

_BACKEND = default_backend()


def get_private_key_bytes(private_key: ec.EllipticCurvePrivateKeyWithSerialization, encoding: Encoding = Encoding.DER,
                          format: PrivateFormat = PrivateFormat.PKCS8,
                          encryption_algorithm: KeySerializationEncryption = NoEncryption()) -> bytes:
    """ Returns the bytes from a cryptography ec.EllipticCurvePrivateKey
    """
    return private_key.private_bytes(encoding=encoding, format=format, encryption_algorithm=encryption_algorithm)


def get_private_key_from_bytes(private_key_bytes: bytes,
                               password: Optional[bytes] = None) -> ec.EllipticCurvePrivateKeyWithSerialization:
    """Returns the cryptography ec.EllipticCurvePrivateKey from bytes"""
    return not_none(load_der_private_key(private_key_bytes, password, _BACKEND))


def get_address_from_public_key(public_key):
    """ Get bytes from public key object and call method that expect bytes

        :param public_key: Public key object
        :param public_key: ec.EllipticCurvePublicKey

        :return: address in bytes
        :rtype: bytes
    """
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    return get_address_from_public_key_bytes(public_key_bytes)


def get_address_from_public_key_bytes(public_key_bytes):
    """ Calculate public key hash and get address from it

        :param public_key_bytes: public key in bytes
        :param public_key_bytes: bytes

        :return: address in bytes
        :rtype: bytes
    """
    public_key_hash = get_hash160(public_key_bytes)
    return get_address_from_public_key_hash(public_key_hash)
