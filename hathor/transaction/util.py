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

import re
import struct
from math import ceil, floor
from typing import Any, Callable, Optional

from hathor.conf.get_settings import get_settings

VerboseCallback = Optional[Callable[[str, Any], None]]


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


def unpack_len(n: int, buf: bytes) -> tuple[bytes, bytes]:
    return buf[:n], buf[n:]


def get_deposit_amount(mint_amount: int) -> int:
    settings = get_settings()
    return ceil(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * mint_amount))


def get_withdraw_amount(melt_amount: int) -> int:
    settings = get_settings()
    return floor(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * melt_amount))


def clean_token_string(string: str) -> str:
    """ Receives the token name/symbol and returns it after some cleanups.
        It sets to uppercase, removes double spaces and spaces at the beginning and end.
    """
    return re.sub(r'\s\s+', ' ', string).strip().upper()
