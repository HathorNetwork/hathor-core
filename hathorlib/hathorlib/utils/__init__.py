# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import re
import struct
from typing import TYPE_CHECKING, Any, Optional, Tuple, TypeVar

from hathorlib.token_amount import UnsignedAmount

if TYPE_CHECKING:
    from hathorlib.conf.settings import HathorSettings

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


_T = TypeVar('_T')


def not_none(optional: Optional[_T], message: str = 'Unexpected `None`') -> _T:
    """Convert an optional to its value. Raises an `AssertionError` if the
    value is `None`"""
    if optional is None:
        raise AssertionError(message)
    return optional


def get_deposit_token_deposit_amount(settings: 'HathorSettings', mint_amount: UnsignedAmount) -> UnsignedAmount:
    numerator = settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR * abs(mint_amount)
    denominator = settings.TOKEN_DEPOSIT_PERCENTAGE_DENOMINATOR
    return ceil_div(numerator, denominator)


def get_deposit_token_withdraw_amount(settings: 'HathorSettings', melt_amount: UnsignedAmount) -> UnsignedAmount:
    numerator = settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR * abs(melt_amount)
    denominator = settings.TOKEN_DEPOSIT_PERCENTAGE_DENOMINATOR
    return numerator // denominator


def ceil_div(a: int, b: int) -> int:
    """
    Calculate ceil division using integer math for non-negative operands, equivalent to `ceil(a / b)` for integers.
    """
    assert a >= 0 and b >= 0
    return (a + b - 1) // b
