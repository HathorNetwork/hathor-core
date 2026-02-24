"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
import hashlib
import re
import struct
from typing import Any, Tuple, Union, cast

import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hathorlib.conf import HathorSettings
from hathorlib.exceptions import InvalidAddress
from hathorlib.serialization import Deserializer, SerializationError, Serializer
from hathorlib.serialization.adapters import MaxBytesExceededError
from hathorlib.serialization.encoding.leb128 import decode_leb128, encode_leb128

settings = HathorSettings()


def int_to_bytes(number: int, size: int, signed: bool = False) -> bytes:
    return number.to_bytes(size, byteorder='big', signed=signed)


def bytes_to_int(data: bytes, *, signed: bool = False) -> int:
    """
    Converts data in bytes to an int. Assumes big-endian format.

    Args:
        data: bytes to be converted
        signed: whether two's complement is used to represent the integer.

    Returns: the converted data as int
    """
    return int.from_bytes(data, byteorder='big', signed=signed)


def unpack(fmt: str, buf: bytes) -> Any:
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[:size]), buf[size:]


def unpack_len(n: int, buf: bytes) -> Tuple[bytes, bytes]:
    return buf[:n], buf[n:]


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


def clean_token_string(string: str) -> str:
    """ Receives the token name/symbol and returns it after some cleanups.
        It sets to uppercase, removes double spaces and spaces at the beginning and end.
    """
    return re.sub(r'\s\s+', ' ', string).strip().upper()


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


def encode_signed(value: int, *, max_bytes: Union[int, None] = None) -> bytes:
    """
    Receive a signed integer and return its LEB128-encoded bytes.

    >>> encode_signed(0) == bytes([0x00])
    True
    >>> encode_signed(624485) == bytes([0xE5, 0x8E, 0x26])
    True
    >>> encode_signed(-123456) == bytes([0xC0, 0xBB, 0x78])
    True
    """
    serializer: Serializer = Serializer.build_bytes_serializer()
    try:
        encode_leb128(serializer.with_optional_max_bytes(max_bytes), value, signed=True)
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot encode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('serialization error') from e
    return bytes(serializer.finalize())


def encode_unsigned(value: int, *, max_bytes: Union[int, None] = None) -> bytes:
    """
    Receive an unsigned integer and return its LEB128-encoded bytes.

    >>> encode_unsigned(0) == bytes([0x00])
    True
    >>> encode_unsigned(624485) == bytes([0xE5, 0x8E, 0x26])
    True
    """
    serializer: Serializer = Serializer.build_bytes_serializer()
    try:
        encode_leb128(serializer.with_optional_max_bytes(max_bytes), value, signed=False)
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot encode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('serialization error') from e
    return bytes(serializer.finalize())


def decode_signed(data: bytes, *, max_bytes: Union[int, None] = None) -> tuple[int, bytes]:
    """
    Receive and consume a buffer returning a tuple of the unpacked
    LEB128-encoded signed integer and the reamining buffer.

    >>> decode_signed(bytes([0x00]) + b'test')
    (0, b'test')
    >>> decode_signed(bytes([0xE5, 0x8E, 0x26]) + b'test')
    (624485, b'test')
    >>> decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test')
    (-123456, b'test')
    >>> decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test', max_bytes=3)
    (-123456, b'test')
    >>> try:
    ...     decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test', max_bytes=2)
    ... except ValueError as e:
    ...     print(e)
    cannot decode more than 2 bytes
    """
    deserializer = Deserializer.build_bytes_deserializer(data)
    try:
        value = decode_leb128(deserializer.with_optional_max_bytes(max_bytes), signed=True)
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot decode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('deserialization error') from e
    remaining_data = bytes(deserializer.read_all())
    deserializer.finalize()
    return (value, remaining_data)


def decode_unsigned(data: bytes, *, max_bytes: Union[int, None] = None) -> tuple[int, bytes]:
    """
    Receive and consume a buffer returning a tuple of the unpacked
    LEB128-encoded unsigned integer and the reamining buffer.

    >>> decode_unsigned(bytes([0x00]) + b'test')
    (0, b'test')
    >>> decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'test')
    (624485, b'test')
    >>> decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'test', max_bytes=3)
    (624485, b'test')
    >>> try:
    ...     decode_unsigned(bytes([0xE5, 0x8E, 0x26]) + b'test', max_bytes=2)
    ... except ValueError as e:
    ...     print(e)
    cannot decode more than 2 bytes
    """
    deserializer = Deserializer.build_bytes_deserializer(data)
    try:
        value = decode_leb128(deserializer.with_optional_max_bytes(max_bytes), signed=False)
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot decode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('deserialization error') from e
    remaining_data = bytes(deserializer.read_all())
    deserializer.finalize()
    return (value, remaining_data)
