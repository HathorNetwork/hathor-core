# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""
This module implements encoding of integers with a fixed size, the size and signedness are parametrized.

The encoding format itself is a standard big-endian format.

>>> se = Serializer.build_bytes_serializer()
>>> encode_int(se, 0, length=1, signed=True)  # writes 00
>>> encode_int(se, 255, length=1, signed=False)  # writes ff
>>> encode_int(se, 1234, length=2, signed=True)  # writes 04d2
>>> encode_int(se, -1234, length=2, signed=True)  # writes fb2e
>>> bytes(se.finalize()).hex()
'00ff04d2fb2e'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('00ff04d2fb2e'))
>>> decode_int(de, length=1, signed=True)  # reads 00
0
>>> decode_int(de, length=1, signed=False)  # reads ff
255
>>> decode_int(de, length=2, signed=True)  # reads 04d2
1234
>>> decode_int(de, length=2, signed=True)  # reads fb2e
-1234
"""

from hathorlib.serialization import Deserializer, Serializer


def encode_int(serializer: Serializer, number: int, *, length: int, signed: bool) -> None:
    """ Encode an int using the given byte-length and signedness.

    This modules's docstring has more details and examples.
    """
    try:
        data = int.to_bytes(number, length, byteorder='big', signed=signed)
    except OverflowError:
        raise ValueError('too big to encode')
    serializer.write_bytes(data)


def decode_int(deserializer: Deserializer, *, length: int, signed: bool) -> int:
    """ Decode an int using the given byte-length and signedness.

    This modules's docstring has more details and examples.
    """
    data = deserializer.read_bytes(length)
    return int.from_bytes(data, byteorder='big', signed=signed)
