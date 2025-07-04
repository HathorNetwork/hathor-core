#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.serialization import Deserializer, SerializationError, Serializer
from hathor.serialization.adapters import MaxBytesExceededError
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128
from hathor.utils.result import Ok, Result, propagate_result


def encode_signed(value: int, *, max_bytes: int | None = None) -> bytes:
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


def encode_unsigned(value: int, *, max_bytes: int | None = None) -> bytes:
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


@propagate_result
def decode_signed(data: bytes, *, max_bytes: int | None = None) -> Result[tuple[int, bytes], SerializationError]:
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
        value = decode_leb128(deserializer.with_optional_max_bytes(max_bytes), signed=True).unwrap_or_propagate()
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot decode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('deserialization error') from e
    remaining_data = bytes(deserializer.read_all().unwrap_or_propagate())
    deserializer.finalize()
    return Ok((value, remaining_data))


@propagate_result
def decode_unsigned(data: bytes, *, max_bytes: int | None = None) -> Result[tuple[int, bytes], SerializationError]:
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
        value = decode_leb128(deserializer.with_optional_max_bytes(max_bytes), signed=False).unwrap_or_propagate()
    except MaxBytesExceededError as e:
        raise ValueError(f'cannot decode more than {max_bytes} bytes') from e
    except SerializationError as e:
        raise ValueError('deserialization error') from e
    remaining_data = bytes(deserializer.read_all().unwrap_or_propagate())
    deserializer.finalize()
    return Ok((value, remaining_data))
