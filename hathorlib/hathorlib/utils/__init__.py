"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
import re
import struct
from typing import Any, Tuple, Union

from hathorlib.serialization import Deserializer, SerializationError, Serializer
from hathorlib.serialization.adapters import MaxBytesExceededError
from hathorlib.serialization.encoding.leb128 import decode_leb128, encode_leb128

# Re-export address utilities from the dedicated module for backward compatibility
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
)


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


def clean_token_string(string: str) -> str:
    """ Receives the token name/symbol and returns it after some cleanups.
        It sets to uppercase, removes double spaces and spaces at the beginning and end.
    """
    return re.sub(r'\s\s+', ' ', string).strip().upper()


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
