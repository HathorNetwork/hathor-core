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
"""


def encode_signed(value: int, *, max_bytes: int | None = None) -> bytes:
    """
    Receive a signed integer and return its LEB128-encoded bytes.

    >>> encode_signed(0) == bytes([0x00])
    True
    >>> encode_signed(624485) == bytes([0xE5, 0x8E, 0x26])
    True
    >>> encode_signed(-123456) == bytes([0xC0, 0xBB, 0x78])
    True
    """
    err_msg = f'cannot encode more than {max_bytes} bytes'
    result = bytearray()
    while True:
        byte = value & 0b0111_1111
        value >>= 7
        if (value == 0 and (byte & 0b0100_0000) == 0) or (value == -1 and (byte & 0b0100_0000) != 0):
            result.append(byte)
            if max_bytes is not None and len(result) > max_bytes:
                raise ValueError(err_msg)
            return result
        result.append(byte | 0b1000_0000)
        if max_bytes is not None and len(result) > max_bytes:
            raise ValueError(err_msg)


def decode_signed(buf: bytes, *, max_bytes: int | None = None) -> tuple[int, bytes]:
    """
    Receive and consume a buffer returning a tuple of the unpacked
    LEB128-encoded signed integer and the reamining buffer.

    >>> decode_signed(bytes([0x00]) + b'test')
    (0, b'test')
    >>> decode_signed(bytes([0xE5, 0x8E, 0x26]) + b'test')
    (624485, b'test')
    >>> decode_signed(bytes([0xC0, 0xBB, 0x78]) + b'test')
    (-123456, b'test')
    """
    byte_list = list(buf)
    result = 0
    shift = 0
    while True:
        byte, *byte_list = byte_list
        result |= (byte & 0b0111_1111) << shift
        shift += 7
        assert shift % 7 == 0
        if max_bytes is not None and shift // 7 > max_bytes:
            raise ValueError(f'cannot decode more than {max_bytes} bytes')
        if (byte & 0b1000_0000) == 0:
            if (byte & 0b0100_0000) != 0:
                return result | -(1 << shift), bytes(byte_list)
            return result, bytes(byte_list)
