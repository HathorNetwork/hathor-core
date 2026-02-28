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
from struct import error as StructError
from typing import TYPE_CHECKING, Any, Callable, Optional

from hathor.transaction.exceptions import InvalidFeeAmount, InvalidOutputValue, TransactionDataError
from hathorlib.utils import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount  # noqa: F401

if TYPE_CHECKING:
    from hathor import TokenUid
    from hathor.conf.settings import HathorSettings

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


def unpack(fmt: str, buf: bytes | memoryview) -> tuple[Any, bytes | memoryview]:
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[:size]), buf[size:]


def unpack_len(n: int, buf: bytes | memoryview) -> tuple[bytes, bytes | memoryview]:
    ret = buf[:n] if isinstance(buf, bytes) else bytes(buf[:n])
    return ret, buf[n:]


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


def bytes_to_output_value(data: bytes) -> tuple[int, bytes]:
    from hathor.serialization import BadDataError, Deserializer
    from hathor.serialization.encoding.output_value import decode_output_value
    deserializer = Deserializer.build_bytes_deserializer(data)
    try:
        output_value = decode_output_value(deserializer)
    except BadDataError as e:
        raise InvalidOutputValue(*e.args)
    remaining_data = deserializer.read_all()
    return (output_value, remaining_data)


def output_value_to_bytes(number: int) -> bytes:
    from hathor.serialization import Serializer
    from hathor.serialization.encoding.output_value import encode_output_value
    serializer = Serializer.build_bytes_serializer()
    try:
        encode_output_value(serializer, number)
    except ValueError as e:
        raise InvalidOutputValue(*e.args)
    return bytes(serializer.finalize())


def validate_token_name_and_symbol(settings: HathorSettings,
                                   token_name: str,
                                   token_symbol: str) -> None:
    """Validate token_name and token_symbol before creating a new token."""
    name_len = len(token_name)
    symbol_len = len(token_symbol)
    if name_len == 0 or name_len > settings.MAX_LENGTH_TOKEN_NAME:
        raise TransactionDataError('Invalid token name length ({})'.format(name_len))
    if symbol_len == 0 or symbol_len > settings.MAX_LENGTH_TOKEN_SYMBOL:
        raise TransactionDataError('Invalid token symbol length ({})'.format(symbol_len))

    # Can't create token with hathor name or symbol
    if clean_token_string(token_name) == clean_token_string(settings.HATHOR_TOKEN_NAME):
        raise TransactionDataError('Invalid token name ({})'.format(token_name))
    if clean_token_string(token_symbol) == clean_token_string(settings.HATHOR_TOKEN_SYMBOL):
        raise TransactionDataError('Invalid token symbol ({})'.format(token_symbol))


def validate_fee_amount(settings: HathorSettings, token_uid: TokenUid | bytes, amount: int) -> None:
    """Validate the fee amount."""
    if amount <= 0:
        raise InvalidFeeAmount(f'fees should be a positive integer, got {amount}')

    if token_uid != settings.HATHOR_TOKEN_UID and amount % settings.FEE_DIVISOR != 0:
        raise InvalidFeeAmount(f'fees using deposit custom tokens should be a multiple of {settings.FEE_DIVISOR}, '
                               f'got {amount}')
