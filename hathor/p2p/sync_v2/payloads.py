# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
