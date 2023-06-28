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

import re
from typing import NamedTuple

# XXX There is a lot of refactor to be done before we can use `NewType`.
#     So, let's skip using NewType until everything is refactored.

VertexId = bytes            # NewType('TxId', bytes)
Address = bytes         # NewType('Address', bytes)
TxOutputScript = bytes  # NewType('TxOutputScript', bytes)
Timestamp = int         # NewType('Timestamp', int)
TokenUid = VertexId     # NewType('TokenUid', VertexId)
Amount = int            # NewType('Amount', int)


class BlockInfo(NamedTuple):
    hash_hex: str
    height: int
    weight: float

    @staticmethod
    def from_raw(block_info_raw: tuple[str, int, float]) -> 'BlockInfo':
        """ Instantiate BlockInfo from a literal tuple.
        """
        if not (isinstance(block_info_raw, list) and len(block_info_raw) == 3):
            raise ValueError(f"block_info_raw must be a tuple with length 3. We got {block_info_raw}.")

        hash_hex, height, weight = block_info_raw

        if not isinstance(hash_hex, str):
            raise ValueError(f"hash_hex must be a string. We got {hash_hex}.")
        hash_pattern = r'[a-fA-F\d]{64}'
        if not re.match(hash_pattern, hash_hex):
            raise ValueError(f"hash_hex must be valid. We got {hash_hex}.")
        if not isinstance(height, int):
            raise ValueError(f"height must be an integer. We got {height}.")
        if height < 0:
            raise ValueError(f"height must greater than or equal to 0. We got {height}.")
        if not isinstance(weight, (float, int)):
            raise ValueError(f"weight must be a float. We got {weight}.")
        if not weight > 0:
            raise ValueError(f"weight must be greater than 0. We got {weight}.")

        return BlockInfo(hash_hex, height, weight)
