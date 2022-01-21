# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import List, NamedTuple, Tuple

from sortedcontainers import SortedKeyList
from structlog import get_logger

logger = get_logger()


class TransactionIndexElement(NamedTuple):
    timestamp: int
    hash: bytes


def get_newest_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', count: int
                               ) -> Tuple[List[bytes], bool]:
    """ Get newest data from a sorted key list
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    newest = key_list[-count:]
    newest.reverse()
    if count >= len(key_list):
        has_more = False
    else:
        has_more = True
    return [tx_index.hash for tx_index in newest], has_more


def get_older_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', timestamp: int,
                              hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
    """ Get sorted key list data from the timestamp/hash_bytes reference to the oldest
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    # Get idx of element
    idx = key_list.bisect_key_left((timestamp, hash_bytes))
    first_idx = max(0, idx - count)
    txs = key_list[first_idx:idx]
    # Reverse because we want the newest first
    txs.reverse()
    return [tx_index.hash for tx_index in txs], first_idx > 0


def get_newer_sorted_key_list(key_list: 'SortedKeyList[TransactionIndexElement]', timestamp: int,
                              hash_bytes: bytes, count: int) -> Tuple[List[bytes], bool]:
    """ Get sorted key list data from the timestamp/hash_bytes reference to the newest
        Return the elements (quantity is the 'count' parameter) and a boolean indicating if has more
    """
    # Get idx of element
    idx = key_list.bisect_key_left((timestamp, hash_bytes))
    last_idx = min(len(key_list), idx + 1 + count)
    txs = key_list[idx + 1:last_idx]
    # Reverse because we want the newest first
    txs.reverse()
    return [tx_index.hash for tx_index in txs], last_idx < len(key_list)
