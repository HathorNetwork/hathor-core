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

def deep_merge(first: dict, second: dict) -> None:
    """
    Recursively merges two dicts, altering the first one in place.

    >>> dict1 = dict(a=1, b=dict(c=2, d=3), e=dict(f=4))
    >>> dict2 = dict(b=dict(d=5, e=6), e=7)
    >>> deep_merge(dict1, dict2)
    >>> dict1 == dict(a=1, b=dict(c=2, d=5, e=6), e=7)
    True
    """
    for key in second:
        if key in first and isinstance(first[key], dict) and isinstance(second[key], dict):
            deep_merge(first[key], second[key])
        else:
            first[key] = second[key]
