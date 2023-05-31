#  Copyright 2023 Hathor Labs
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

from typing import Optional


def get_bit_list(n: int, min_size: Optional[int] = None) -> list[int]:
    """
    Returns a list of bits corresponding to a non-negative number, with LSB on the left.

    Args:
        n: the number
        min_size: if set, pads the returned list with zeroes until it reaches min_size

    >>> get_bit_list(0b0)
    []
    >>> get_bit_list(0b1)
    [1]
    >>> get_bit_list(0b10)
    [0, 1]
    >>> get_bit_list(0b111001010)
    [0, 1, 0, 1, 0, 0, 1, 1, 1]
    >>> get_bit_list(0b0, min_size=4)
    [0, 0, 0, 0]
    >>> get_bit_list(0b1, min_size=3)
    [1, 0, 0]
    >>> get_bit_list(0b10, min_size=1)
    [0, 1]
    >>> get_bit_list(0b111001010, min_size=10)
    [0, 1, 0, 1, 0, 0, 1, 1, 1, 0]
    """
    assert n >= 0

    shifts = range(n.bit_length())
    bits = [n >> shift & 1 for shift in shifts]
    padding_zeroes = [] if min_size is None else [0] * (min_size - len(bits))

    return bits + padding_zeroes
