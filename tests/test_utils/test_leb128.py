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

import random

import pytest

from hathor.utils import leb128


@pytest.mark.parametrize(
    ['value', 'expected'],
    [
        (2, bytes([2])),
        (-2, bytes([0x7e])),
        (127, bytes([127 + 0x80, 0])),
        (-127, bytes([1 + 0x80, 0x7f])),
        (128, bytes([0 + 0x80, 1])),
        (-128, bytes([0 + 0x80, 0x7f])),
        (129, bytes([1 + 0x80, 1])),
        (-129, bytes([0x7f + 0x80, 0x7e])),
    ],
)
def test_encode_dwarf_examples(value: int, expected: bytes) -> None:
    """
    Examples from the DWARF 5 standard, section 7.6, table 7.8.
    https://dwarfstd.org/doc/DWARF5.pdf
    """
    assert leb128.encode_signed(value) == expected


def _assert_round_trip(n: int) -> None:
    assert leb128.decode_signed(leb128.encode_signed(n) + b'extra bytes') == (n, b'extra bytes'), n


@pytest.mark.parametrize(
    ['value'],
    [
        (0,),
        (2,),
        (-2,),
        (127,),
        (-127,),
        (128,),
        (-128,),
        (129,),
        (-129,),
    ]
)
def test_round_trip_dwarf_examples(value: int) -> None:
    _assert_round_trip(value)


def test_round_trip_edge_cases() -> None:
    for n_bytes in range(0, 33):
        n = 8 * n_bytes
        edge_cases = (-(2**n) - 1, -(2**n), 2**n - 1, 2**n)
        for value in edge_cases:
            _assert_round_trip(value)


def test_round_trip_random() -> None:
    for _ in range(1_000_000):
        n = random.randint(-(2**256) - 1, 2**256)
        _assert_round_trip(n)


@pytest.mark.parametrize(
    ['value', 'max_bytes'],
    [
        (2, 0),
        (-2, 0),
        (127, 1),
        (-127, 1),
        (128, 1),
        (-128, 1),
        (129, 1),
        (-129, 1),
    ],
)
def test_encode_max_bytes_dwarf_examples(value: int, max_bytes: int) -> None:
    with pytest.raises(ValueError) as e:
        leb128.encode_signed(value, max_bytes=max_bytes)
    assert str(e.value) == f'cannot encode more than {max_bytes} bytes'


@pytest.mark.parametrize(
    ['buf', 'max_bytes'],
    [
        (bytes([2]), 0),
        (bytes([0x7e]), 0),
        (bytes([127 + 0x80, 0]), 1),
        (bytes([1 + 0x80, 0x7f]), 1),
        (bytes([0 + 0x80, 1]), 1),
        (bytes([0 + 0x80, 0x7f]), 1),
        (bytes([1 + 0x80, 1]), 1),
        (bytes([0x7f + 0x80, 0x7e]), 1),
    ],
)
def test_decode_max_bytes_dwarf_examples(buf: bytes, max_bytes: int) -> None:
    with pytest.raises(ValueError) as e:
        leb128.decode_signed(buf, max_bytes=max_bytes)
    assert str(e.value) == f'cannot decode more than {max_bytes} bytes'
