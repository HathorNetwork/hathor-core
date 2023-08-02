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
