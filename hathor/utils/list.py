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

from typing import List, Optional, TypeVar

T = TypeVar('T')


def single_or_none(_list: List[T]) -> Optional[T]:
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
