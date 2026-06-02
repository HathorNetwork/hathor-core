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

r"""
This module implements our custom output-value encoding for integers.

Our custom encoding format consists of the following:

- if value <= 2**31 - 1, use 4-bytes and encode it as a signed positive integer
- if value > 2**31 - 1, use 8-bytes and encode it as a signed negative integer

When decoding, we peek at the first byte to determine the sign and whether read 4 or 8 bytes.

Examples:

>>> se = Serializer.build_bytes_serializer()
>>> try:
...     encode_output_value_v1(se, 0)
... except ValueError as e:
...     print(*e.args)
Number must be strictly positive

>>> try:
...     encode_output_value_v1(se, -1)
... except ValueError as e:
...     print(*e.args)
Number must not be negative

>>> se = Serializer.build_bytes_serializer()
>>> encode_output_value_v1(se, 0, strict=False)  # writes 00000000
>>> encode_output_value_v1(se, 100)  # writes 00000064
>>> encode_output_value_v1(se, 2 ** 31 - 1)  # writes 7fffffff
>>> encode_output_value_v1(se, 2 ** 31)  # writes ffffffff80000000
>>> encode_output_value_v1(se, 2 ** 63)  # writes 8000000000000000
>>> bytes(se.finalize()).hex()
'00000000000000647fffffffffffffff800000008000000000000000'

>>> se = Serializer.build_bytes_serializer()
>>> try:
...     encode_output_value_v1(se, 2 ** 63 + 1)
... except ValueError as e:
...     print(*e.args)
Number is too big; max possible value is 2**63, got: 9223372036854775809

>>> de = Deserializer.build_bytes_deserializer(b'\x00\x00\x00\x00')
>>> try:
...     decode_output_value_v1(de)
... except ValueError as e:
...     print(*e.args)
Number must be strictly positive

>>> data = bytes.fromhex('00000000000000647fffffffffffffff800000008000000000000000') + b'test'
>>> de = Deserializer.build_bytes_deserializer(data)
>>> decode_output_value_v1(de, strict=False)  # reads 00000000
0
>>> decode_output_value_v1(de)  # reads 00000064
100
>>> decode_output_value_v1(de)  # reads 7fffffff
2147483647
>>> decode_output_value_v1(de)  # reads ffffffff80000000
2147483648
>>> decode_output_value_v1(de)  # reads 8000000000000000
9223372036854775808
>>> bytes(de.read_all())
b'test'
>>> de.finalize()

V2 roundtrips:

>>> def roundtrip_v2(value, **kwargs):
...     se = Serializer.build_bytes_serializer()
...     encode_output_value_v2(se, value, **kwargs)
...     data = bytes(se.finalize())
...     de = Deserializer.build_bytes_deserializer(data)
...     result = decode_output_value_v2(de, **kwargs)
...     de.finalize()
...     return data.hex(), result
>>> roundtrip_v2(1) == ('0101', 1)
True
>>> roundtrip_v2(0xff) == ('01ff', 0xff)
True
>>> roundtrip_v2(0xff00) == ('02ff00', 0xff00)
True
>>> roundtrip_v2(0xc0ffee) == ('03c0ffee', 0xc0ffee)
True
>>> roundtrip_v2(256 ** 14) == ('0f010000000000000000000000000000', 256 ** 14)
True
>>> roundtrip_v2(2 ** 113) == ('0f020000000000000000000000000000', 2 ** 113)
True
>>> roundtrip_v2(MAX_OUTPUT_VALUE_V2) == ('0f11c37937e080000000000000000000', MAX_OUTPUT_VALUE_V2)
True
>>> roundtrip_v2(0, strict=False) == ('00', 0)
True
"""

import struct

from typing_extensions import assert_never

from hathorlib.decimal_places import VertexDecimalVersion
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.exceptions import BadDataError

MAX_OUTPUT_VALUE_32 = 2 ** 31 - 1  # max value (inclusive) before having to use 8 bytes: 2_147_483_647
MAX_OUTPUT_VALUE_64 = 2 ** 63  # max value (inclusive) that can be encoded (with 8 bytes): 9_223_372_036_854_775_808

MAX_OUTPUT_VALUE_V2: int = MAX_OUTPUT_VALUE_64 * 10**16
MAX_OUTPUT_VALUE_V2_LENGTH: int = (MAX_OUTPUT_VALUE_V2.bit_length() + 7) // 8


def encode_output_value(serializer: Serializer, value: int, *, decimal_version: VertexDecimalVersion) -> None:
    match decimal_version:
        case VertexDecimalVersion.V1:
            encode_output_value_v1(serializer, value)
        case VertexDecimalVersion.V2:
            encode_output_value_v2(serializer, value)
        case _:
            assert_never(decimal_version)


def encode_output_value_v1(serializer: Serializer, number: int, *, strict: bool = True) -> None:
    """ Encodes either 4 or 8 bytes using our output-value format.

    This modules's docstring has more details and examples.
    """
    assert isinstance(number, int)
    if number < 0:
        raise ValueError('Number must not be negative')
    if strict and number == 0:
        raise ValueError('Number must be strictly positive')
    if number > MAX_OUTPUT_VALUE_64:
        raise ValueError(f'Number is too big; max possible value is 2**63, got: {number}')
    # XXX: `signed` makes no difference, but oh well
    if number > MAX_OUTPUT_VALUE_32:
        serializer.write_bytes((-number).to_bytes(8, byteorder='big', signed=True))
    else:
        serializer.write_bytes(number.to_bytes(4, byteorder='big', signed=True))


def encode_output_value_v2(serializer: Serializer, value: int, *, strict: bool = True) -> None:
    """
    Encode an output value for decimal version V2, using length-prefix encoding.

    >>> def encode(value, *, strict=True):
    ...     se = Serializer.build_bytes_serializer()
    ...     encode_output_value_v2(se, value, strict=strict)
    ...     return bytes(se.finalize()).hex()
    >>> encode(-1)
    Traceback (most recent call last):
    ...
    ValueError: value must be not be negative
    >>> encode(0)
    Traceback (most recent call last):
    ...
    ValueError: value must not be zero
    >>> encode(0, strict=False)
    '00'
    >>> encode(MAX_OUTPUT_VALUE_V2 + 1)
    Traceback (most recent call last):
    ...
    ValueError: value is too big; max is 92233720368547758080000000000000000, got: 92233720368547758080000000000000001
    >>> encode(MAX_OUTPUT_VALUE_V2)
    '0f11c37937e080000000000000000000'
    >>> encode(2 ** 113)
    '0f020000000000000000000000000000'
    >>> encode(256 ** 14)
    '0f010000000000000000000000000000'
    >>> encode(1)
    '0101'
    >>> encode(2)
    '0102'
    >>> encode(3)
    '0103'
    >>> encode(0xff)
    '01ff'
    >>> encode(0xff00)
    '02ff00'
    >>> encode(0xc0ffee)
    '03c0ffee'
    """
    if value < 0:
        raise ValueError('value must be not be negative')

    if value == 0:
        if strict:
            raise ValueError('value must not be zero')
        serializer.write_byte(0)
        return

    if value > MAX_OUTPUT_VALUE_V2:
        raise ValueError(f'value is too big; max is {MAX_OUTPUT_VALUE_V2}, got: {value}')

    length = (value.bit_length() + 7) // 8
    payload = value.to_bytes(length, byteorder='big')

    assert len(payload) == length
    assert length <= MAX_OUTPUT_VALUE_V2_LENGTH
    assert payload[0] != 0

    serializer.write_byte(length)
    serializer.write_bytes(payload)


def decode_output_value(deserializer: Deserializer, *, decimal_version: VertexDecimalVersion) -> int:
    match decimal_version:
        case VertexDecimalVersion.V1:
            return decode_output_value_v1(deserializer)
        case VertexDecimalVersion.V2:
            return decode_output_value_v2(deserializer)
        case _:
            assert_never(decimal_version)


def decode_output_value_v1(deserializer: Deserializer, *, strict: bool = True) -> int:
    """ Decodes either 4 or 8 bytes using our output-value format.

    This modules's docstring has more details and examples.
    """
    value_high_byte, = deserializer.peek_struct('!b')
    try:
        if value_high_byte < 0:
            raw_value, = deserializer.read_struct('!q')
            value = -raw_value
        else:
            value, = deserializer.read_struct('!i')
    except struct.error as e:
        raise BadDataError('Invalid byte struct for output') from e
    assert value >= 0
    if strict and value == 0:
        raise ValueError('Number must be strictly positive')
    if value <= MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
        raise ValueError('Value fits in 4 bytes but is using 8 bytes')
    return value


def decode_output_value_v2(deserializer: Deserializer, *, strict: bool = True) -> int:
    """
    Decode and output value for decimal version V2, using length-prefix encoding.

    >>> build = lambda hex_value: Deserializer.build_bytes_deserializer(bytes.fromhex(hex_value))
    >>> decode_output_value_v2(build(''))
    Traceback (most recent call last):
    ...
    hathorlib.serialization.exceptions.OutOfDataError: not enough bytes to read
    >>> decode_output_value_v2(build('00'))
    Traceback (most recent call last):
    ...
    ValueError: value must not be zero
    >>> decode_output_value_v2(build('00'), strict=False)
    0
    >>> decode_output_value_v2(build('10'))
    Traceback (most recent call last):
    ...
    ValueError: length is too big; max is 15, got: 16
    >>> decode_output_value_v2(build('0f 020000000000000000000000000000')) == 2 ** 113
    True
    >>> decode_output_value_v2(build('0f 11c37937e080000000000000000001'))
    Traceback (most recent call last):
    ...
    ValueError: value is too big; max is 92233720368547758080000000000000000, got: 92233720368547758080000000000000001
    >>> decode_output_value_v2(build('0f 11c37937e080000000000000000000')) == MAX_OUTPUT_VALUE_V2
    True
    >>> decode_output_value_v2(build('0f 010000000000000000000000000000')) == 256 ** 14
    True
    >>> decode_output_value_v2(build('01'))
    Traceback (most recent call last):
    ...
    hathorlib.serialization.exceptions.OutOfDataError: not enough bytes to read
    >>> decode_output_value_v2(build('03 ffff'))
    Traceback (most recent call last):
    ...
    hathorlib.serialization.exceptions.OutOfDataError: not enough bytes to read
    >>> decode_output_value_v2(build('01 00'))
    Traceback (most recent call last):
    ...
    ValueError: non-canonical encoding, leading zero byte: 00
    >>> decode_output_value_v2(build('01 ff')) == 0xff
    True
    >>> decode_output_value_v2(build('02 00ff'))
    Traceback (most recent call last):
    ...
    ValueError: non-canonical encoding, leading zero byte: 00ff
    >>> decode_output_value_v2(build('02 ff00')) == 0xff00
    True
    >>> decode_output_value_v2(build('01 01'))
    1
    >>> decode_output_value_v2(build('01 02'))
    2
    >>> decode_output_value_v2(build('01 03'))
    3
    >>> decode_output_value_v2(build('03 c0ffee')) == 0xc0ffee
    True
    """
    length = deserializer.read_byte()
    if length == 0:
        if strict:
            raise ValueError('value must not be zero')
        return 0

    if length > MAX_OUTPUT_VALUE_V2_LENGTH:
        raise ValueError(f'length is too big; max is {MAX_OUTPUT_VALUE_V2_LENGTH}, got: {length}')

    payload = deserializer.read_bytes(length)
    if payload[0] == 0:
        raise ValueError(f'non-canonical encoding, leading zero byte: {payload.hex()}')

    value = int.from_bytes(payload, byteorder='big')
    if value > MAX_OUTPUT_VALUE_V2:
        raise ValueError(f'value is too big; max is {MAX_OUTPUT_VALUE_V2}, got: {value}')

    return value
