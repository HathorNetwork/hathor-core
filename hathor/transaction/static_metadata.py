#  Copyright 2024 Hathor Labs
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

import dataclasses
from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


@dataclass(slots=True, frozen=True, kw_only=True)
class VertexStaticMetadata(ABC):
    """
    Static Metadata represents vertex attributes that are not intrinsic to the vertex data, but can be calculated from
    only the vertex itself and its dependencies, and whose values never change.

    This class is an abstract base class for all static metadata types that includes attributes common to all vertex
    types.
    """
    min_height: int

    def to_bytes(self) -> bytes:
        """Convert this static metadata instance to a json bytes representation."""
        return json_dumpb(dataclasses.asdict(self))

    @classmethod
    def from_bytes(cls, data: bytes, *, target: 'BaseTransaction') -> 'VertexStaticMetadata':
        """Create a static metadata instance from a json bytes representation, with a known vertex type target."""
        from hathor.transaction import Block, Transaction
        json_dict = json_loadb(data)

        if isinstance(target, Block):
            return BlockStaticMetadata(**json_dict)

        if isinstance(target, Transaction):
            return TransactionStaticMetadata(**json_dict)

        raise NotImplementedError


@dataclass(slots=True, frozen=True, kw_only=True)
class BlockStaticMetadata(VertexStaticMetadata):
    height: int
    feature_activation_bit_counts: list[int]


@dataclass(slots=True, frozen=True, kw_only=True)
class TransactionStaticMetadata(VertexStaticMetadata):
    pass
