import struct
from math import ceil, floor

from hathor.conf import HathorSettings

settings = HathorSettings()


def int_to_bytes(number: int, size: int, signed: bool = False) -> bytes:
    return number.to_bytes(size, byteorder='big', signed=signed)


def unpack(fmt: str, buf: bytes):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[:size]), buf[size:]


def unpack_len(n: int, buf: bytes):
    return buf[:n], buf[n:]


def get_deposit_amount(mint_amount: int) -> int:
    return ceil(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * mint_amount))


def get_withdraw_amount(melt_amount: int) -> int:
    return floor(abs(settings.TOKEN_DEPOSIT_PERCENTAGE * melt_amount))
