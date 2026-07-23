# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
