# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
    bits = []

    while n > 0:
        bits.append(n & 1)
        n >>= 1

    if min_size is not None:
        while len(bits) < min_size:
            bits.append(0)

    return bits
