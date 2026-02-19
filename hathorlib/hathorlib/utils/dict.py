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

from copy import deepcopy
from typing import Any, TypeVar

K = TypeVar('K')


def deep_merge(first_dict: dict[K, Any], second_dict: dict[K, Any]) -> dict[K, Any]:
    """
    Recursively merges two dicts, returning a new one with the merged values. Keeps both input dicts intact.

    Note: will raise RecursionError if there's a circular reference in both dicts.

    >>> dict1 = dict(a=1, b=dict(c=2, d=3), e=dict(f=4))
    >>> dict2 = dict(b=dict(d=5, e=6), e=7)
    >>> result = deep_merge(dict1, dict2)
    >>> result == dict(a=1, b=dict(c=2, d=5, e=6), e=7)
    True
    >>> dict1 == dict(a=1, b=dict(c=2, d=3), e=dict(f=4))
    True
    >>> dict2 == dict(b=dict(d=5, e=6), e=7)
    True
    """
    merged = deepcopy(first_dict)

    def do_deep_merge(first: dict[K, Any], second: dict[K, Any]) -> dict[K, Any]:
        for key in second:
            if key in first and isinstance(first[key], dict) and isinstance(second[key], dict):
                do_deep_merge(first[key], second[key])
            else:
                first[key] = second[key]

        return first

    return do_deep_merge(merged, second_dict)
