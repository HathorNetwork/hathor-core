# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Iterable, TypeVar

T = TypeVar('T')


def batch_iterator(iterator: Iterable[T], batch_size: int) -> Iterable[list[T]]:
    """
    Yield batches of up to batch_size items from iterator.

    >>> list(batch_iterator([], 10))
    []
    >>> list(batch_iterator([1, 2, 3, 4], 1))
    [[1], [2], [3], [4]]
    >>> list(batch_iterator([1, 2, 3, 4], 2))
    [[1, 2], [3, 4]]
    >>> list(batch_iterator([1, 2, 3, 4], 3))
    [[1, 2, 3], [4]]
    >>> list(batch_iterator([1, 2, 3, 4], 4))
    [[1, 2, 3, 4]]
    """
    assert batch_size >= 1
    batch = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []

    if batch:
        yield batch
