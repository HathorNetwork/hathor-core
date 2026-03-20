# Copyright 2023 Hathor Labs
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

from hathor.types import VertexId
from hathor.utils.pydantic import BaseModel, Hex


class PayloadBaseModel(BaseModel):
    """Base model for P2P message payloads with automatic hex encoding for bytes fields."""
    pass


class GetNextBlocksPayload(PayloadBaseModel):
    """GET-NEXT-BLOCKS message is used to request a stream of blocks in the best blockchain."""
    start_hash: Hex[VertexId]
    end_hash: Hex[VertexId]
    quantity: int


class BestBlockPayload(PayloadBaseModel):
    """BEST-BLOCK message is used to send information about the current best block."""
    block: Hex[VertexId]
    height: int


class GetTransactionsBFSPayload(PayloadBaseModel):
    """GET-TRANSACTIONS-BFS message is used to request a stream of transactions confirmed by blocks."""
    start_from: list[Hex[VertexId]]
    first_block_hash: Hex[VertexId]
    last_block_hash: Hex[VertexId]
