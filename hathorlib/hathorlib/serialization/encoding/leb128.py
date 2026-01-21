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

"""
This module implements LEB128 for signed integers.

LEB128 or Little Endian Base 128 is a variable-length code compression used to store arbitrarily large
integers in a small number of bytes. LEB128 is used in the DWARF debug file format and the WebAssembly
binary encoding for all integer literals.

References:
- https://en.wikipedia.org/wiki/LEB128
- https://dwarfstd.org/doc/DWARF5.pdf
- https://webassembly.github.io/spec/core/binary/values.html#integers

This module implements LEB128 encoding/decoding using the standard 1-byte block split into 1-bit for continuation and
7-bits for data. The data can be either a signed or unsigned integer.

>>> se = Serializer.build_bytes_serializer()
>>> se.write_bytes(b'test')  # writes 74657374
>>> encode_leb128(se, 0, signed=True)  # writes 00
>>> encode_leb128(se, 624485, signed=True)  # writes e58e26
>>> encode_leb128(se, -123456, signed=True)  # writes c0bb78
>>> bytes(se.finalize()).hex()
'7465737400e58e26c0bb78'

>>> data = bytes.fromhex('00 e58e26 c0bb78 74657374')
>>> de = Deserializer.build_bytes_deserializer(data)
>>> decode_leb128(de, signed=True)  # reads 00
0
>>> decode_leb128(de, signed=True)  # reads e58e26
624485
>>> decode_leb128(de, signed=True)  # reads c0bb78
-123456
>>> bytes(de.read_all())  # reads 74657374
b'test'
>>> de.finalize()
"""

from hathorlib.serialization import Deserializer, Serializer


def encode_leb128(serializer: Serializer, value: int, *, signed: bool) -> None:
    """ Encodes an integer using LEB128.

    Caller must explicitly choose `signed=True` or `signed=False`.

    This module's docstring has more details on LEB128 and examples.
    """
    if not signed and value < 0:
        raise ValueError('cannot encode value <0 as unsigend')
    while True:
        byte = value & 0b0111_1111
        value >>= 7
        if signed:
            cont = (value == 0 and (byte & 0b0100_0000) == 0) or (value == -1 and (byte & 0b0100_0000) != 0)
        else:
            cont = (value == 0 and (byte & 0b1000_0000) == 0)
        if cont:
            serializer.write_byte(byte)
            break
        serializer.write_byte(byte | 0b1000_0000)


def decode_leb128(deserializer: Deserializer, *, signed: bool) -> int:
    """ Decodes a LEB128-encoded integer.

    Caller must explicitly choose `signed=True` or `signed=False`.

    This module's docstring has more details on LEB128 and examples.
    """
    result = 0
    shift = 0
    while True:
        byte = deserializer.read_byte()
        result |= (byte & 0b0111_1111) << shift
        shift += 7
        assert shift % 7 == 0
        if (byte & 0b1000_0000) == 0:
            if signed and (byte & 0b0100_0000) != 0:
                return result | -(1 << shift)
            return result
