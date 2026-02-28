"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
import hashlib
from typing import cast

import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hathorlib.conf import HathorSettings
from hathorlib.exceptions import InvalidAddress

settings = HathorSettings()


def get_checksum(address_bytes: bytes) -> bytes:
    """ Calculate double sha256 of address and gets first 4 bytes

        :param address_bytes: address before checksum
        :param address_bytes: bytes

        :return: checksum of the address
        :rtype: bytes
    """
    return hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]


def decode_address(address58: str) -> bytes:
    """ Decode address in base58 to bytes

    :param address58: Wallet address in base58
    :type address58: string

    :raises InvalidAddress: if address58 is not a valid base58 string or
                            not a valid address or has invalid checksum

    :return: Address in bytes
    :rtype: bytes
    """
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


def get_address_b58_from_bytes(address: bytes) -> str:
    """Encode address bytes to base58 string.

        :param address: address in bytes
        :type address: bytes

        :return: address in base 58
        :rtype: string
    """
    return base58.b58encode(address).decode('utf-8')


def get_address_b58_from_public_key_hash(public_key_hash: bytes) -> str:
    """Gets the b58 address from the hash of a public key.

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    address = get_address_from_public_key_hash(public_key_hash)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_public_key_hash(public_key_hash: bytes,
                                     version_byte: bytes = settings.P2PKH_VERSION_BYTE) -> bytes:
    """Gets the address in bytes from the public key hash

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    address = b''
    # Version byte
    address += version_byte
    # Pubkey hash
    address += public_key_hash
    checksum = get_checksum(address)
    address += checksum
    return address


def get_address_b58_from_redeem_script_hash(redeem_script_hash: bytes,
                                            version_byte: bytes = settings.MULTISIG_VERSION_BYTE) -> str:
    """Gets the b58 address from the hash of the redeem script in multisig.

        :param redeem_script_hash: hash of the redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    address = get_address_from_redeem_script_hash(redeem_script_hash, version_byte)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_redeem_script_hash(redeem_script_hash: bytes,
                                        version_byte: bytes = settings.MULTISIG_VERSION_BYTE) -> bytes:
    """Gets the address in bytes from the redeem script hash

        :param redeem_script_hash: hash of redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    address = b''
    # Version byte
    address += version_byte
    # redeem script hash
    address += redeem_script_hash
    checksum = get_checksum(address)
    address += checksum
    return address


def get_public_key_from_bytes_compressed(public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Return the cryptography public key from the compressed bytes format."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)


def get_address_b58_from_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Get the b58 address from a public key."""
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    return get_address_b58_from_public_key_bytes(public_key_bytes)


def get_address_b58_from_public_key_bytes(public_key_bytes: bytes) -> str:
    """Get the b58 address from a public key bytes."""
    public_key_hash = get_hash160(public_key_bytes)
    return get_address_b58_from_public_key_hash(public_key_hash)


def get_public_key_bytes_compressed(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Return the bytes of a pubkey in the compressed format."""
    return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


try:
    hashlib.new('ripemd160', b'')
except Exception:
    # XXX: the source says "Test-only pure Python RIPEMD160 implementation", however for our case this is acceptable
    #      for more details see: https://github.com/bitcoin/bitcoin/pull/23716/files which has a copy of the same code
    import pycoin.contrib.ripemd160  # type: ignore[import-untyped]

    def get_hash160(public_key_bytes: bytes) -> bytes:
        """The input is hashed twice: first with SHA-256 and then with RIPEMD-160"""
        key_hash = hashlib.sha256(public_key_bytes)
        return cast(bytes, pycoin.contrib.ripemd160.ripemd160(key_hash.digest()))
else:
    def get_hash160(public_key_bytes: bytes) -> bytes:
        """The input is hashed twice: first with SHA-256 and then with RIPEMD-160"""
        key_hash = hashlib.sha256(public_key_bytes)
        h = hashlib.new('ripemd160')
        h.update(key_hash.digest())
        return h.digest()
