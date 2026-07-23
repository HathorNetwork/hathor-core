# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, TypeVar

T = TypeVar('T')


def single_or_none(_list: list[T]) -> Optional[T]:
    """Function to convert a list with at most one element to the given element or None.
    >>> single_or_none([]) is None
    True
    >>> single_or_none([1])
    1
    >>> single_or_none([1, 2])
    Traceback (most recent call last):
     ...
    AssertionError: expected one value at most
    """
    assert len(_list) <= 1, 'expected one value at most'

    return None if not len(_list) else _list[0]
