# Copyright 2024 Hathor Labs
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

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from hathor.transaction import Block

if TYPE_CHECKING:
    from hathor.transaction.poa import PoaBlock

BLOCK_WEIGHT_IN_TURN = 2.0
BLOCK_WEIGHT_OUT_OF_TURN = 1.0
SIGNER_ID_LEN = 2


def get_hashed_poa_data(block: PoaBlock) -> bytes:
    """Get the data to be signed for the Proof-of-Authority."""
    poa_data = block.get_funds_struct()
    poa_data += Block.get_graph_struct(block)  # We call Block's to exclude poa fields
    poa_data += block.get_struct_nonce()
    hashed_poa_data = hashlib.sha256(poa_data).digest()
    return hashed_poa_data
