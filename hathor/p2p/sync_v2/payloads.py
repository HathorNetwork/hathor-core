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

from pydantic import validator

from hathor.types import VertexId
from hathor.utils.pydantic import BaseModel


class PayloadBaseModel(BaseModel):

    @classmethod
    def convert_hex_to_bytes(cls, value: str | VertexId) -> VertexId:
        """Convert a string in hex format to bytes. If bytes are given, it does nothing."""
        if isinstance(value, str):
            return bytes.fromhex(value)
        elif isinstance(value, VertexId):
            return value
        raise ValueError('invalid type')

    class Config:
        json_encoders = {
            VertexId: lambda x: x.hex()
        }


class GetNextBlocksPayload(PayloadBaseModel):
    """GET-NEXT-BLOCKS message is used to request a stream of blocks in the best blockchain."""

    start_hash: VertexId
    end_hash: VertexId
    quantity: int

    @validator('start_hash', 'end_hash', pre=True)
    def validate_bytes_fields(cls, value: str | bytes) -> VertexId:
        return cls.convert_hex_to_bytes(value)


class BestBlockPayload(PayloadBaseModel):
    """BEST-BLOCK message is used to send information about the current best block."""

    block: VertexId
    height: int

    @validator('block', pre=True)
    def validate_bytes_fields(cls, value: str | VertexId) -> VertexId:
        return cls.convert_hex_to_bytes(value)


class GetTransactionsBFSPayload(PayloadBaseModel):
    """GET-TRANSACTIONS-BFS message is used to request a stream of transactions confirmed by blocks."""
    start_from: list[VertexId]
    first_block_hash: VertexId
    last_block_hash: VertexId

    @validator('first_block_hash', 'last_block_hash', pre=True)
    def validate_bytes_fields(cls, value: str | VertexId) -> VertexId:
        return cls.convert_hex_to_bytes(value)

    @validator('start_from', pre=True, each_item=True)
    def validate_start_from(cls, value: str | VertexId) -> VertexId:
        return cls.convert_hex_to_bytes(value)
