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
...     encode_output_value(se, 0)
... except ValueError as e:
...     print(*e.args)
Number must be strictly positive

>>> try:
...     encode_output_value(se, -1)
... except ValueError as e:
...     print(*e.args)
Number must not be negative

>>> se = Serializer.build_bytes_serializer()
>>> encode_output_value(se, 0, strict=False)  # writes 00000000
>>> encode_output_value(se, 100)  # writes 00000064
>>> encode_output_value(se, 2 ** 31 - 1)  # writes 7fffffff
>>> encode_output_value(se, 2 ** 31)  # writes ffffffff80000000
>>> encode_output_value(se, 2 ** 63)  # writes 8000000000000000
>>> bytes(se.finalize()).hex()
'00000000000000647fffffffffffffff800000008000000000000000'

>>> se = Serializer.build_bytes_serializer()
>>> try:
...     encode_output_value(se, 2 ** 63 + 1)
... except ValueError as e:
...     print(*e.args)
Number is too big; max possible value is 2**63, got: 9223372036854775809

>>> de = Deserializer.build_bytes_deserializer(b'\x00\x00\x00\x00')
>>> try:
...     decode_output_value(de)
... except ValueError as e:
...     print(*e.args)
Number must be strictly positive

>>> data = bytes.fromhex('00000000000000647fffffffffffffff800000008000000000000000') + b'test'
>>> de = Deserializer.build_bytes_deserializer(data)
>>> decode_output_value(de, strict=False)  # reads 00000000
0
>>> decode_output_value(de)  # reads 00000064
100
>>> decode_output_value(de)  # reads 7fffffff
2147483647
>>> decode_output_value(de)  # reads ffffffff80000000
2147483648
>>> decode_output_value(de)  # reads 8000000000000000
9223372036854775808
>>> bytes(de.read_all())
b'test'
>>> de.finalize()
"""

import struct

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.exceptions import BadDataError, SerializationError
from hathor.utils.result import Err, Ok, Result, propagate_result

MAX_OUTPUT_VALUE_32 = 2 ** 31 - 1  # max value (inclusive) before having to use 8 bytes: 2_147_483_647
MAX_OUTPUT_VALUE_64 = 2 ** 63  # max value (inclusive) that can be encoded (with 8 bytes): 9_223_372_036_854_775_808


def encode_output_value(
    serializer: Serializer,
    number: int,
    *,
    strict: bool = True,
) -> Result[None, SerializationError]:
    """ Encodes either 4 or 8 bytes using our output-value format.

    This modules's docstring has more details and examples.
    """
    assert isinstance(number, int)
    if number < 0:
        return Err(SerializationError('Number must not be negative'))
    if strict and number == 0:
        return Err(SerializationError('Number must be strictly positive'))
    if number > MAX_OUTPUT_VALUE_64:
        return Err(SerializationError(f'Number is too big; max possible value is 2**63, got: {number}'))
    # XXX: `signed` makes no difference, but oh well
    if number > MAX_OUTPUT_VALUE_32:
        serializer.write_bytes((-number).to_bytes(8, byteorder='big', signed=True))
    else:
        serializer.write_bytes(number.to_bytes(4, byteorder='big', signed=True))

    return Ok(None)


@propagate_result
def decode_output_value(deserializer: Deserializer, *, strict: bool = True) -> Result[int, SerializationError]:
    """ Decodes either 4 or 8 bytes using our output-value format.

    This modules's docstring has more details and examples.
    """
    value_high_byte, = deserializer.peek_struct('!b').unwrap_or_propagate()
    try:
        if value_high_byte < 0:
            raw_value, = deserializer.read_struct('!q').unwrap_or_propagate()
            value = -raw_value
        else:
            value, = deserializer.read_struct('!i').unwrap_or_propagate()
    except struct.error as e:
        return Err(BadDataError('Invalid byte struct for output'), e)
    assert value >= 0
    if strict and value == 0:
        return Err(SerializationError('Number must be strictly positive'))
    if value < MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
        return Err(SerializationError('Value fits in 4 bytes but is using 8 bytes'))
    return Ok(value)
