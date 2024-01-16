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

import hashlib
from typing import Optional

import base58
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
)

from hathor.conf.get_settings import get_global_settings
from hathor.util import not_none

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


try:
    hashlib.new('ripemd160', b'')
except Exception:
    # XXX: the source says "Test-only pure Python RIPEMD160 implementation", however for our case this is acceptable
    #      for more details see: https://github.com/bitcoin/bitcoin/pull/23716/files which has a copy of the same code
    import pycoin.contrib.ripemd160

    def get_hash160(public_key_bytes: bytes) -> bytes:
        """The input is hashed twice: first with SHA-256 and then with RIPEMD-160"""
        key_hash = hashlib.sha256(public_key_bytes)
        return pycoin.contrib.ripemd160.ripemd160(key_hash.digest())
else:
    def get_hash160(public_key_bytes: bytes) -> bytes:
        """The input is hashed twice: first with SHA-256 and then with RIPEMD-160"""
        key_hash = hashlib.sha256(public_key_bytes)
        h = hashlib.new('ripemd160')
        h.update(key_hash.digest())
        return h.digest()


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


def get_address_b58_from_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Gets the b58 address from a public key.

    :param: ec.EllipticCurvePublicKey
    :return: the b58-encoded address
    :rtype: string
    """
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    return get_address_b58_from_public_key_bytes(public_key_bytes)


def get_address_b58_from_public_key_hash(public_key_hash: bytes) -> str:
    """Gets the b58 address from the hash of a public key.

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    address = get_address_from_public_key_hash(public_key_hash)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_public_key_hash(public_key_hash: bytes, version_byte: Optional[bytes] = None) -> bytes:
    """Gets the address in bytes from the public key hash

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    settings = get_global_settings()
    address = b''
    actual_version_byte: bytes = version_byte if version_byte is not None else settings.P2PKH_VERSION_BYTE
    # Version byte
    address += actual_version_byte
    # Pubkey hash
    address += public_key_hash
    checksum = get_checksum(address)
    address += checksum
    return address


def get_checksum(address_bytes: bytes) -> bytes:
    """ Calculate double sha256 of address and gets first 4 bytes

        :param address_bytes: address before checksum
        :param address_bytes: bytes

        :return: checksum of the address
        :rtype: bytes
    """
    return hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]


def get_address_b58_from_public_key_bytes(public_key_bytes: bytes) -> str:
    """Gets the b58 address from a public key bytes.

        :param public_key_bytes: public key in bytes
        :param public_key_bytes: bytes

        :return: address in base 58
        :rtype: string
    """
    public_key_hash = get_hash160(public_key_bytes)
    return get_address_b58_from_public_key_hash(public_key_hash)


def get_address_b58_from_bytes(address):
    """Gets the b58 address from the address in bytes

        :param address: bytes

        :return: address in base 58
        :rtype: string
    """
    return base58.b58encode(address).decode('utf-8')


def get_public_key_bytes_compressed(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """ Returns the bytes from a cryptography ec.EllipticCurvePublicKey in a compressed format

        :param public_key: Public key object
        :type public_key: ec.EllipticCurvePublicKey

        :rtype: bytes
    """
    return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def get_public_key_from_bytes_compressed(public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """ Returns the cryptography public key from the compressed bytes format

        :param public_key_bytes: Compressed format of public key in bytes
        :type public_key_bytes: bytes

        :rtype: ec.EllipticCurvePublicKey
    """
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)


def get_address_b58_from_redeem_script_hash(redeem_script_hash: bytes, version_byte: Optional[bytes] = None) -> str:
    """Gets the b58 address from the hash of the redeem script in multisig.

        :param redeem_script_hash: hash of the redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    settings = get_global_settings()
    actual_version_byte: bytes = version_byte if version_byte is not None else settings.MULTISIG_VERSION_BYTE
    address = get_address_from_redeem_script_hash(redeem_script_hash, actual_version_byte)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_redeem_script_hash(redeem_script_hash: bytes, version_byte: Optional[bytes] = None) -> bytes:
    """Gets the address in bytes from the redeem script hash

        :param redeem_script_hash: hash of redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    settings = get_global_settings()
    actual_version_byte: bytes = version_byte if version_byte is not None else settings.MULTISIG_VERSION_BYTE
    address = b''
    # Version byte
    address += actual_version_byte
    # redeem script hash
    address += redeem_script_hash
    checksum = get_checksum(address)
    address += checksum
    return address


def decode_address(address58: str) -> bytes:
    """ Decode address in base58 to bytes

    :param address58: Wallet address in base58
    :type address58: string

    :raises InvalidAddress: if address58 is not a valid base58 string or
                            not a valid address or has invalid checksum

    :return: Address in bytes
    :rtype: bytes
    """
    from hathor.wallet.exceptions import InvalidAddress
    try:
        decoded_address = base58.b58decode(address58)
    except ValueError:
        # Invalid base58 string
        raise InvalidAddress('Invalid base58 address')
    # Validate address size [25 bytes]
    if len(decoded_address) != 25:
        raise InvalidAddress('Address size must have 25 bytes')
    # Validate the checksum
    address_checksum = decoded_address[-4:]
    valid_checksum = get_checksum(decoded_address[:-4])
    if address_checksum != valid_checksum:
        raise InvalidAddress('Invalid checksum of address')
    return decoded_address


def is_pubkey_compressed(pubkey: bytes) -> bool:
    """ Receives a public key bytes and return True if in CompressedPoint format
        This function will not test if this is a valid public key.
        Only the byte that signals the format is tested.
    """
    if len(pubkey) == 0:
        return False
    # CompressedPoint encoding always starts with the bits "0000 001_"
    # UncompressedPoint always starts with the bits "0000 0100"
    # so testing if the first byte is 2 or 3 will make sure that this is an Unconpressed public key
    # https://www.secg.org/sec1-v2.pdf [2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion]
    return pubkey[0] in [0x02, 0x03]
