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
This module implements ECV (Exponential-continuation Varint) for integers (signed or unsigned).

ECV is based on LEB128, but instead of using a continuation bit on every byte, it uses a continuation bit every 2**N
bytes, that means each continuation bit implies a doubling in size, instead of a 1-byte increase. This change means
that the amount of continuation bits is proportional to O(log(N)) instead of O(N) for an integer of size N bytes.

- Layout is little-endian across bytes (like LEB128).
- Bytes at 1-based positions that are powers of two are *control* bytes:
  MSB = continuation flag, lower 7 bits are payload.
- Other bytes are full 8-bit payload bytes.
- Total length is always a power of two (1, 2, 4, 8, ... bytes).

>>> se = Serializer.build_bytes_serializer()
>>> se.write_bytes(b'test')  # writes 74657374
>>> encode_ecv(se, 0, signed=True)  # writes 00
>>> encode_ecv(se, 624485, signed=False)  # writes e58e2600
>>> encode_ecv(se, -123456, signed=True)  # writes c0bbf87f
>>> bytes(se.finalize()).hex()
'7465737400e58e2600c0bbf87f'

>>> data = bytes.fromhex('00 e58e2600 c0bbf87f 74657374')
>>> de = Deserializer.build_bytes_deserializer(data)
>>> decode_ecv(de, signed=True)  # reads 00
0
>>> decode_ecv(de, signed=False)  # reads e58e2600
624485
>>> decode_ecv(de, signed=True)  # reads c0bbf87f
-123456
>>> bytes(de.read_all())  # reads 74657374
b'test'
>>> de.finalize()
"""

from hathor.serialization import Deserializer, Serializer


def _is_pow2(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def encode_ecv(serializer: Serializer, value: int, *, signed: bool) -> None:
    """ Encodes an integer using ECV.

    Caller must explicitly choose `signed=True` or `signed=False`.

    This module's docstring has more details on ECV and examples.
    """
    if not signed and value < 0:
        raise ValueError('cannot encode value <0 as unsigend')
    pos = 1
    while True:
        if _is_pow2(pos):
            byte = value & 0b0111_1111
            value >>= 7
            if signed:
                cont = (value == 0 and (byte & 0b0100_0000) == 0) or (value == -1 and (byte & 0b0100_0000) != 0)
            else:
                cont = (value == 0 and (byte & 0b1000_0000) == 0)
            if cont:
                serializer.write_byte(byte)
                break
            else:
                byte |= 0b1000_0000
        else:
            byte = value & 0b1111_1111
            value >>= 8
        serializer.write_byte(byte)
        pos += 1


def decode_ecv(deserializer: Deserializer, *, signed: bool) -> int:
    """ Decodes an ECV-encoded integer.

    Caller must explicitly choose `signed=True` or `signed=False`.

    This module's docstring has more details on ECV and examples.
    """
    result = 0
    shift = 0
    pos = 1
    while True:
        byte = deserializer.read_byte()
        if _is_pow2(pos):
            result |= (byte & 0b0111_1111) << shift
            shift += 7
            if (byte & 0b1000_0000) == 0:
                if signed and (byte & 0b0100_0000) != 0:
                    return result | -(1 << shift)
                else:
                    return result
        else:
            result |= byte << shift
            shift += 8
        pos += 1
