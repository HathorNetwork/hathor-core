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

from __future__ import annotations

import re
import struct
from math import ceil, floor
from struct import error as StructError
from typing import TYPE_CHECKING, Any, Callable, Optional

from hathor.transaction.exceptions import InvalidOutputValue

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings

VerboseCallback = Optional[Callable[[str, Any], None]]

MAX_OUTPUT_VALUE_32 = 2 ** 31 - 1  # max value (inclusive) before having to use 8 bytes: 2147483647 ~= 2.14748e+09


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


def unpack(fmt: str, buf: bytes | memoryview) -> tuple[Any, bytes | memoryview]:
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[:size]), buf[size:]


def unpack_len(n: int, buf: bytes | memoryview) -> tuple[bytes, bytes | memoryview]:
    ret = buf[:n] if isinstance(buf, bytes) else bytes(buf[:n])
    return ret, buf[n:]


def get_deposit_amount(settings: HathorSettings, mint_amount: int) -> int:
    return ceil(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * mint_amount))


def get_withdraw_amount(settings: HathorSettings, melt_amount: int) -> int:
    return floor(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * melt_amount))


def clean_token_string(string: str) -> str:
    """ Receives the token name/symbol and returns it after some cleanups.
        It sets to uppercase, removes double spaces and spaces at the beginning and end.
    """
    return re.sub(r'\s\s+', ' ', string).strip().upper()


def decode_string_utf8(encoded: bytes, key: str) -> str:
    """ Raises StructError in case it's not a valid utf-8 string
    """
    try:
        decoded = encoded.decode('utf-8')
        return decoded
    except UnicodeDecodeError:
        raise StructError('{} must be a valid utf-8 string.'.format(key))


def bytes_to_output_value(buf: bytes) -> tuple[int, bytes]:
    (value_high_byte,), _ = unpack('!b', buf)
    if value_high_byte < 0:
        output_struct = '!q'
        value_sign = -1
    else:
        output_struct = '!i'
        value_sign = 1
    try:
        (signed_value,), buf = unpack(output_struct, buf)
    except StructError as e:
        raise InvalidOutputValue('Invalid byte struct for output') from e
    value = signed_value * value_sign
    assert value >= 0
    if value < MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
        raise ValueError('Value fits in 4 bytes but is using 8 bytes')
    return value, buf


def output_value_to_bytes(number: int) -> bytes:
    if number <= 0:
        raise InvalidOutputValue('Invalid value for output')

    if number > MAX_OUTPUT_VALUE_32:
        return (-number).to_bytes(8, byteorder='big', signed=True)
    else:
        return number.to_bytes(4, byteorder='big', signed=True)  # `signed` makes no difference, but oh well
